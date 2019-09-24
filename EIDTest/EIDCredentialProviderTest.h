
void Menu_CREDENTIALUID();
void Menu_CREDENTIALUID_ADMIN();
void Menu_CREDENTIALUID_ONLY_EID();
void menu_CREDENTIALUID_OldBehavior();
void menu_CRED_COM();
void menu_ResetPasswordWizard();
void menu_CREDSSP_DEL_REG();
void menu_CREDSSP_ADD_REG();

enum AuthenticationType
{
	LSA,
	SSPI,
	Negociate,
	NTLM,
	CredSSP,
};

void SetAuthentication(AuthenticationType type);