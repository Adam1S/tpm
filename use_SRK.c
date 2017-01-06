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

#define DBG(message, tResult) printf("Line%d, %s) %s returned 0x%08x. %s.\n", __LINE__, __func__, message, tResult,(char *)Trspi_Error_String(tResult));

int main(int argc, char **argv){
 TSS_HCONTEXT	hContext;
 TSS_HTPM	hTPM;
 TSS_RESULT	result;
 TSS_HKEY	hSRK=0;
 TSS_HPOLICY	hSRKPolicy=0, hKeyPolicy=0;
 TSS_UUID	SRK_UUID=TSS_UUID_SRK;
 BYTE		wks[20]; //for the well known secret
 TSS_UUID	keyUUID={1,2,3,4,5,6,7,8,9,10,2};
 TSS_HKEY	hKey=0;
 memset(wks,0,20);

 result=Tspi_Context_Create(&hContext);
 DBG("Create Context",result);

 result=Tspi_Context_Connect(hContext, NULL);
 DBG("Conntect Context", result);


 result=Tspi_Context_GetTpmObject(hContext,
				&hTPM);
 DBG("Get tpm obj", result); 

 result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
							SRK_UUID, &hSRK);
 DBG("Load SRK Key", result);

 result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hSRKPolicy );
 DBG("Get SRK Policy", result);



 return 0;
}
