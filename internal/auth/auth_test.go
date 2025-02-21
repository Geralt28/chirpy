package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMakeAndValidateJWT(t *testing.T) {
	// Generate a test user ID
	userID := uuid.New()
	secret := "testsecret"
	expiration := time.Minute * 5 // Token valid for 5 minutes

	// Create a JWT
	token, err := MakeJWT(userID, secret, expiration)
	assert.NoError(t, err, "MakeJWT should not return an error")
	assert.NotEmpty(t, token, "Generated token should not be empty")

	// Validate the JWT
	parsedUserID, err := ValidateJWT(token, secret)
	assert.NoError(t, err, "ValidateJWT should not return an error for a valid token")
	assert.Equal(t, userID, parsedUserID, "User ID should match the one in the JWT")
}

func TestExpiredJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testsecret"
	expiration := -time.Minute // Token already expired

	token, err := MakeJWT(userID, secret, expiration)
	assert.NoError(t, err, "MakeJWT should not return an error for expired token generation")

	_, err = ValidateJWT(token, secret)
	assert.Error(t, err, "ValidateJWT should return an error for expired token")
}

func TestInvalidSecretJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testsecret"
	wrongSecret := "wrongsecret"
	expiration := time.Minute * 5

	token, err := MakeJWT(userID, secret, expiration)
	assert.NoError(t, err, "MakeJWT should not return an error")

	_, err = ValidateJWT(token, wrongSecret)
	assert.Error(t, err, "ValidateJWT should return an error when using the wrong secret")
}

func TestInvalidTokenFormat(t *testing.T) {
	invalidToken := "this.is.not.a.valid.jwt"
	secret := "testsecret"

	_, err := ValidateJWT(invalidToken, secret)
	assert.Error(t, err, "ValidateJWT should return an error for an invalid token format")
}
