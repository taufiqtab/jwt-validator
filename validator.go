package validator

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var payload jwt.MapClaims

func GetPayload() jwt.MapClaims {
	return payload
}

func isExpired() bool {

	status := false
	now := time.Now()
	exp := int64(payload["exp"].(float64))

	expDate := time.Unix(exp, 0)
	if now.After(expDate) {
		status = true
	}

	return status
}

func ValidateJWT(c *gin.Context) {

	SECRET := []byte(os.Getenv("SECRET"))
	token := c.GetHeader("Authorization")
	jwtToken := strings.Split(token, " ")

	if token != "" {
		token, err := jwt.Parse(jwtToken[1], func(t *jwt.Token) (interface{}, error) {

			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Not Authorized"})
			}
			return SECRET, nil

		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Not Authorized" + err.Error()})
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			payload = claims

			expired := isExpired()
			if expired {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Token Expired"})
			} else {
				c.Next()
			}
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "invalid"})
		}
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Not Authorized"})
	}
}
