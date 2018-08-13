package providers

import (
	au "github.com/altenrion/tests/auth"
	"github.com/dgrijalva/jwt-go"
	"time"
	"fmt"
	)


type JWTProvider struct{
	UserCredentials au.Credentials
	JWTSecretKey string
	JWTExpirationDelta int
	UserTokensSearcher func(credentials au.Credentials) (string,error)
}

func (p JWTProvider) GetToken() (string, error){

	token, err := p.UserTokensSearcher(p.UserCredentials)
	if err != nil {
		return "", fmt.Errorf("failed tokens searching : [%s]", err)
	}
	if token == "" {
		var genErr error
		token, genErr = generateToken(p)
		if genErr != nil {
			return "", fmt.Errorf("failed token generation : [%s]", genErr)

		}
	}

	// here we have token
	return token, nil
}

func generateToken(provider JWTProvider) (string, error) {

	// Create JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	//header. todo: check if it is needed at all?

	tokenHeader := make(map[string]interface{})
	tokenHeader["typ"] = "JWT"
	tokenHeader["testHeader"] = "Test"
	token.Header = tokenHeader

	//todo: add here correct claims for JWT + Kong
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(provider.JWTExpirationDelta)).Unix()
	claims["iat"] = time.Now().Unix()
	claims["userid"] = provider.UserCredentials.Login
	claims["testPayload"] = "Test"

	payload, payloadErr:= getUserSpecificPayLoad(provider)
	if payloadErr != nil {
		return "", fmt.Errorf("failed payload : [%s]", payloadErr)
	}

	//todo: has to modify insertion of payload into token
	claims["payload"] = payload

	token.Claims = claims

	tokenString, err := token.SignedString([]byte(provider.JWTSecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to create token : [%s]", err)

	}

	return tokenString, nil
}

func getUserSpecificPayLoad(provider JWTProvider) ([]string, error){

	//todo: find accessments
	//todo: think over what else to insert into token

	return nil, nil
}