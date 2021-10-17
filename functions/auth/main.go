package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang-jwt/jwt"
)

type JWK struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

var jwk JWK

func init() {
	cognitoRegion := "ap-northeast-2"

	cognitoPoolID := os.Getenv("COGNITO_POOL_ID")
	if cognitoPoolID == "" {
		panic(fmt.Errorf("env COGNITO_POOL_ID not set"))
	}

	cognitoIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", cognitoRegion, cognitoPoolID)

	resp, err := http.Get(cognitoIssuer)
	if err != nil {
		panic(fmt.Errorf("failed getting public keys; %w", err))
	}

	defer resp.Body.Close()

	json.NewDecoder(resp.Body).Decode(&jwk)
}

func main() {
	lambda.Start(handler)
}

func handler(request events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {

	tokenSlice := strings.Split(request.AuthorizationToken, " ")

	if tokenSlice[0] != "Bearer" {
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("it's not bearer token")
	}

	token, err := jwt.Parse(tokenSlice[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		key := findKey(jwk.Keys, token.Header["kid"].(string))
		if key == nil {
			return nil, fmt.Errorf("can't find key for kid `%s`", token.Header["kid"])
		}

		return convertKey(key.E, key.N)
	})
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("can't parse jwt; %w", err)
	}

	if !token.Valid {
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return events.APIGatewayCustomAuthorizerResponse{}, fmt.Errorf("can't get claims")
	}

	return generatePolicy(
		"user",
		"Allow",
		request.MethodArn,
		map[string]interface{}{"email": claims["email"]},
	), nil
}

func findKey(keys []Key, kid string) *Key {
	for _, e := range keys {
		if e.Kid == kid {
			return &e
		}
	}
	return nil
}

func convertKey(rawE, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, err
	}

	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}

	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}

	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, err
	}

	pubKey.N.SetBytes(decodedN)

	return pubKey, nil
}

func generatePolicy(
	principalID, effect, resource string,
	context map[string]interface{},
) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	authResponse.Context = context

	return authResponse
}
