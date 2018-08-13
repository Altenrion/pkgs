package auth


type Credentials struct {
    Login string
    Password string
}

type AuthorisationService struct {
    Identity AuthorisationProvider
//        aup.LdapProvider{
//Config:aup.LdapConfig{
//UserCredentials : credentials,
//
////todo: make this section correct & dynamic| maybe env vars
//
//LdapServer : "ad.example.com:389",
//LdapBind : "search@example.com",
//LdapPassword : "Password123!",
//
//FilterDN : "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=Chat,CN=Users,DC=example,DC=com)(|(sAMAccountName={username})(mail={username})))",
//BaseDN : "CN=Users,DC=example,DC=com",
//},
//},

    Token TokenProvider
//    : aup.JWTProvider{
//UserCredentials:    credentials,
//
////todo: make this env vars
//JWTExpirationDelta: 20,
//JWTSecretKey:       "SomeCoolSecretKey",
//UserTokensSearcher: TokenSearcher,
}

func(a AuthorisationService) Authorize() (bool, error){
    _, conErr := a.Identity.Connect()
	if conErr != nil {

	}

    _, idErr := a.Identity.Identify()
	if idErr != nil {

	}
    return true, nil
}

func(a AuthorisationService) Tokenize() (string, error){
	token, err := a.Token.GetToken()
	if err != nil {

	}
	return token, nil
}



type AuthorisationProvider interface {
    Connect()(bool, error)
    Disconnect()
    Identify()(bool, error)
}

type TokenProvider interface {
    GetToken()(string, error)
}


