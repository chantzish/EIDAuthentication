
#define CHECK_SIGNATUREONLY 0
#define CHECK_TRUST 1
#define CHECK_CRYPTO 2
#define CHECK_MAX 3

class CContainerHolderTest
{
public:
	CContainerHolderTest(CContainer* pContainer);

	virtual ~CContainerHolderTest();
	void Release();

	DWORD GetIconIndex();
	BOOL IsTrusted();
	BOOL SupportEncryption();
	BOOL HasSignatureUsageOnly();
	//BOOL HasCurrentUserName();

	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags){return S_OK;}
	CContainer* GetContainer();

	int GetCheckCount();
	int GetImage(DWORD dwCheckNum);
	PTSTR GetDescription(DWORD dwCheckNum);
	PTSTR GetSolveDescription(DWORD dwCheckNum);
	BOOL Solve(DWORD dwCheckNum);
private:
	CContainer* _pContainer;
	BOOL _IsTrusted;
	BOOL _SupportEncryption;
//	BOOL _HasCurrentUserName;
	DWORD _dwTrustError;
};
