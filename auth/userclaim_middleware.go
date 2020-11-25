package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo"
)

func UserClaimMiddleware(skipPaths ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {

		return func(c echo.Context) error {
			for _, t := range skipPaths {
				if strings.HasPrefix(c.Path(), t) {
					return next(c)
				}
			}

			req := c.Request()
			userClaim, err := newUserClaimFromHttpReq(req)
			if err != nil {
				return err
			}

			c.SetRequest(req.WithContext(context.WithValue(req.Context(), userClaimContextName, userClaim)))

			return next(c)
		}
	}
}

func newUserClaimFromHttpReq(req *http.Request) (UserClaim, error) {
	token := req.Header.Get("Authorization")
	tokenErr := echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	if token == "" {
		return UserClaim{}, tokenErr
	}

	userClaim, err := UserClaim{}.FromToken(token)
	if err != nil {
		return UserClaim{}, tokenErr
	}

	userClaim.Username = req.Header.Get("X-Username")
	userClaim.UserId, _ = strconv.ParseInt(req.Header.Get("X-User-Id"), 10, 64)

	return userClaim, nil
}

func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
