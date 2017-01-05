#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define DBG(message, tResult) printf("Line%d, %s) %s returned 0x%08x. \x1B[32m %s\x1B[0m.\n", __LINE__, __func__, message, tResult,(char *)Trspi_Error_String(tResult));

int main(int argc, char **argv){

 TSS_HCONTEXT hContext=0; 
 TSS_HTPM hTPM= 0; 
 TSS_RESULT result;
 TSS_HKEY hSRK = 0; 
 TSS_HPOLICY hSRKPolicy=0, keyUsagePolicy=0;
 TSS_UUID SRK_UUID = TSS_UUID_SRK;
 TSS_UUID createdKeyUUID={1,2,3,4,5,6,7,8,9,10,2};
 TSS_FLAG initFlags;
 TSS_HKEY hKey=0;

 BYTE wks[20];  
 
 memset(wks,0,20);

 initFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 |
	    TSS_KEY_NON_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;
 
 result =
 Tspi_Context_Create(&hContext);  
 DBG(" Create a Context\n",result);  
 result=
 Tspi_Context_Connect(hContext, NULL); 
 DBG(" Connect to TPM\n", result);
 // Get the TPM handle
 result=
 Tspi_Context_GetTpmObject(hContext, &hTPM); 
 DBG(" GetTPM Handle\n",result); 
 // Get the SRK handle

 result =
 Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					      initFlags, &hKey);
 DBG( "Create Object with init flags", result);

result=
 Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);  
 DBG(" Tspi_Context_Connect\n",result); 
 //Get the SRK policy
 result=
 Tspi_GetPolicyObject(hSRK,  TSS_POLICY_USAGE, &hSRKPolicy); 
 DBG(" Get TPM Policy\n" ,result );
 // Then we set the SRK policy to be the well known secret
 result=
 Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20, wks);  
 DBG(" Set password to TPM Policy", result);

 result =
 Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
			&keyUsagePolicy);
 DBG(" Create policy for new key", result);

result=
 Tspi_Policy_SetSecret(keyUsagePolicy,TSS_SECRET_MODE_SHA1,20, wks);
 DBG(" Set password to new policy", result);

 result = Tspi_Policy_AssignToObject(keyUsagePolicy, hKey);
 DBG(" Assign this policy to new key", result);
 
 DBG(" Created new key", result); 

 result = Tspi_Context_RegisterKey(hContext,
									hKey, TSS_PS_TYPE_SYSTEM, 
									createdKeyUUID,
									TSS_PS_TYPE_SYSTEM,
									SRK_UUID);
 DBG(" Registered Key", result);


 Tspi_Context_FreeMemory(hContext, NULL);
 Tspi_Context_Close(hContext);
 return 0;
}
