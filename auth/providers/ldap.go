package providers

import (
	"fmt"
	"strings"
	"gopkg.in/ldap.v2"
	au "github.com/altenrion/tests/auth"
)

type LdapProvider struct {
	Connection *ldap.Conn
	Config LdapConfig
}

type LdapConfig struct{
	LdapServer string
	LdapBind string
	LdapPassword string

	FilterDN string
	BaseDN string

	UserCredentials au.Credentials
}

func (p LdapProvider) Connect() (bool, error){

	conn, err := connect(p.Config)
	if err != nil {
		return false, err
	}
	p.Connection = conn

	return true, nil
}

func (p LdapProvider) Disconnect(){
	p.Connection.Close()
}

func (p LdapProvider) Identify() (bool, error){

	if err := auth(p.Config, p.Connection); err != nil {
		fmt.Printf("%v", err)
		return false, err
	}

	return true, nil
}


func connect(conf LdapConfig) (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", conf.LdapServer)
	if err != nil {
		return nil, fmt.Errorf("failed to dial. %s", err)
	}

	if err := conn.Bind(conf.LdapBind, conf.LdapPassword); err != nil {
		return nil, fmt.Errorf("failed to bind. %s", err)
	}

	return conn, nil
}


func auth(conf LdapConfig, conn *ldap.Conn) error {
	result, err := conn.Search(ldap.NewSearchRequest(
		conf.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter(conf, conf.UserCredentials.Login),
		[]string{"dn"},
		nil,
	))

	if err != nil {
		return fmt.Errorf("failed to find user. %s", err)
	}

	if len(result.Entries) < 1 {
		return fmt.Errorf("user does not exist")
	}

	if len(result.Entries) > 1 {
		return fmt.Errorf("too many entries returned")
	}

	if err := conn.Bind(result.Entries[0].DN, conf.UserCredentials.Password); err != nil {
		return fmt.Errorf("failed to auth. %s", err)
	}
	fmt.Printf("Authenticated successfuly!")

	return nil
}

func filter(conf LdapConfig, needle string) string {
	res := strings.Replace(
		conf.FilterDN,
		"{username}",
		needle,
		-1,
	)

	return res
}

//func list(conn *ldap.Conn) error {
//	result, err := conn.Search(ldap.NewSearchRequest(
//		baseDN,
//		ldap.ScopeWholeSubtree,
//		ldap.NeverDerefAliases,
//		0,
//		0,
//		false,
//		filter("*"),
//		[]string{"dn", "sAMAccountName", "mail", "sn", "givenName"},
//		nil,
//	))
//
//	if err != nil {
//		return fmt.Errorf("Failed to search users. %s", err)
//	}
//
//	for _, entry := range result.Entries {
//		fmt.Printf(
//			"%s: %s %s -- %v -- %v\n",
//			entry.DN,
//			entry.GetAttributeValue("givenName"),
//			entry.GetAttributeValue("sn"),
//			entry.GetAttributeValue("sAMAccountName"),
//			entry.GetAttributeValue("mail"),
//		)
//	}
//
//	return nil
//}
