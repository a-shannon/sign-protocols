package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	_interface "rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/models"
)

type admissionTestApp struct {
	_interface.RosenTss
	keygens     map[string]_interface.KeygenOperation
	signs       map[string]_interface.SignOperation
	keygenErr   error
	signErr     error
	keygenReads int
	signReads   int
}

func (a *admissionTestApp) GetKeygenOperations() map[string]_interface.KeygenOperation {
	a.keygenReads++
	return a.keygens
}

func (a *admissionTestApp) GetSignOperations() map[string]_interface.SignOperation {
	a.signReads++
	return a.signs
}

func (a *admissionTestApp) StartNewKeygen(models.KeygenMessage) error { return a.keygenErr }
func (a *admissionTestApp) StartNewSign(models.SignMessage) error     { return a.signErr }

type admissionTestKeygen struct {
	_interface.KeygenOperation
	class string
}

func (o admissionTestKeygen) GetClassName() string { return o.class }

type admissionTestSign struct {
	_interface.SignOperation
	class string
}

func (o admissionTestSign) GetClassName() string { return o.class }

func TestAdmissionControllerReadsOppositeSnapshot(t *testing.T) {
	for _, crypto := range []string{models.ECDSA, models.EDDSA} {
		t.Run(crypto, func(t *testing.T) {
			a := &admissionTestApp{
				keygens: map[string]_interface.KeygenOperation{"active": admissionTestKeygen{class: crypto + "Keygen"}},
				signs:   map[string]_interface.SignOperation{"active": admissionTestSign{class: crypto + "Sign"}},
			}
			controller := &tssController{rosenTss: a}
			if err := controller.checkKeygenOperation(crypto); err == nil || err.Error() != crypto+"Sign "+models.OperationIsRunningError {
				t.Fatalf("keygen precheck: %v", err)
			}
			if a.signReads != 1 || a.keygenReads != 0 {
				t.Fatalf("keygen getter calls sign=%d keygen=%d", a.signReads, a.keygenReads)
			}
			if err := controller.checkSignOperation(crypto); err == nil || err.Error() != crypto+"Keygen "+models.OperationIsRunningError {
				t.Fatalf("sign precheck: %v", err)
			}
			if a.signReads != 1 || a.keygenReads != 1 {
				t.Fatalf("sign getter calls sign=%d keygen=%d", a.signReads, a.keygenReads)
			}
			other := models.ECDSA
			if crypto == models.ECDSA {
				other = models.EDDSA
			}
			a.keygens["active"] = admissionTestKeygen{class: other + "Keygen"}
			a.signs["active"] = admissionTestSign{class: other + "Sign"}
			if err := controller.checkKeygenOperation(crypto); err != nil {
				t.Fatalf("unrelated sign blocked keygen: %v", err)
			}
			if err := controller.checkSignOperation(crypto); err != nil {
				t.Fatalf("unrelated keygen blocked sign: %v", err)
			}
		})
	}
}

func TestAdmissionControllerLateConflictIs409(t *testing.T) {
	logging = zap.NewNop().Sugar()
	for _, crypto := range []string{models.ECDSA, models.EDDSA} {
		for _, kind := range []string{"keygen", "sign"} {
			t.Run(crypto+"/"+kind, func(t *testing.T) {
				a := &admissionTestApp{}
				controller := &tssController{rosenTss: a, validator: validator.New()}
				e := echo.New()
				e.Validator = controller
				var body string
				var handler echo.HandlerFunc
				if kind == "keygen" {
					a.keygenErr = fmt.Errorf("%s "+models.OperationIsRunningError, crypto+"Sign")
					body = fmt.Sprintf(`{"peersCount":1,"threshold":1,"crypto":%q,"callBackUrl":"local","p2pIDs":["local"],"operationTimeout":1}`, crypto)
					handler = controller.Keygen()
				} else {
					a.signErr = fmt.Errorf("%s "+models.OperationIsRunningError, crypto+"Keygen")
					body = fmt.Sprintf(`{"crypto":%q,"message":"00","callBackUrl":"local","peers":[{}],"operationTimeout":1,"chainCode":"local","derivationPath":[1]}`, crypto)
					handler = controller.Sign()
				}
				req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
				ctx := e.NewContext(req, httptest.NewRecorder())
				err := handler(ctx)
				httpErr, ok := err.(*echo.HTTPError)
				if !ok || httpErr.Code != http.StatusConflict {
					t.Fatalf("late conflict response: %v", err)
				}
				if kind == "keygen" && (a.signReads != 1 || a.keygenReads != 0) {
					t.Fatalf("keygen preliminary reads sign=%d keygen=%d", a.signReads, a.keygenReads)
				}
				if kind == "sign" && (a.keygenReads != 1 || a.signReads != 0) {
					t.Fatalf("sign preliminary reads keygen=%d sign=%d", a.keygenReads, a.signReads)
				}
			})
		}
	}
}
