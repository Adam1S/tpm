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
 TSS_HCONTEXT	hContext=0;
 TSS_HTPM	hTPM=0;
 TSS_FLAG	initFlags;
 TSS_HKEY	hKey;
 TSS_RESULT	result;
 TSS_HKEY	hSRK=0;
 TSS_HPOLICY	srkUsagePolicy=0, keyUsagePolicy=0;
 TSS_UUID	SRK_UUID=TSS_UUID_SRK;
 BYTE		wks[20];
 memset(wks, 0, 20);

 initFlags= TSS_KEY_TYPE_BIND 
	| TSS_KEY_SIZE_2048 
	| TSS_KEY_VOLATILE 
	| TSS_KEY_AUTHORIZATION 
	| TSS_KEY_MIGRATABLE;

 printf("\x1B[31mWitaj we wspanialym programie Mistrzu! \x1B[0m \n");

 result=
  Tspi_Context_Create(&hContext);
 DBG("Create Context",result);

 result=
  Tspi_Context_Connect(hContext,NULL);
 DBG("Context Connect", result);
 
 result=
  Tspi_Context_GetTpmObject(hContext, &hTPM);
 DBG("Get TPM Object", result);

 result=
  Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
							initFlags, &hKey);
 DBG("Create Object", result);

 result=Tspi_Context_LoadKeyByUUID(hContext,
							TSS_PS_TYPE_SYSTEM, SRK_UUID,
							&hSRK);
 DBG("Load SRK by UUID", result);

 result=
  Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
							&srkUsagePolicy);
 DBG("Get SRK Policy", result);

 result=
  Tspi_Policy_SetSecret(srkUsagePolicy,
							TSS_SECRET_MODE_SHA1,
							20,
							wks);
 DBG("Set SRK Policy secret", result);

 result=
  Tspi_Policy_AssignToObject(keyUsagePolicy, hKey);
 DBG("Assign Policy to New Key", result);

 Tspi_Context_FreeMemory(hContext, NULL);
 Tspi_Context_Close(hContext);
 return 0;
}
