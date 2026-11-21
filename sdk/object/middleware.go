package object

import (
	"strings"

	"github.com/valyala/fasthttp/fasthttpadaptor"
	"github.com/zap-proto/zip"
)

// Middleware serves the process-wide store's signed links under Prefix and passes
// every other request on. The host and each standalone plugin mount it, so a link
// signed by any process on the volume is answered by whichever the browser reaches.
func Middleware() zip.Handler {
	serve := fasthttpadaptor.NewFastHTTPHandler(Handler())
	return func(c *zip.Ctx) error {
		if !strings.HasPrefix(c.Path(), Prefix) {
			return c.Continue()
		}
		serve(c.Fiber().RequestCtx())
		return nil
	}
}
