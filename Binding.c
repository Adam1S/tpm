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
 TSS_UUID bindingKeyUUID={1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 2};
 TSS_FLAG initFlags;
 TSS_HKEY hKey=0;
 BYTE wks[20];  

 BYTE adam[]="Wojskowa Akademia Techniczna";
 
 memset(wks,0,20);
 
 result=
 Tspi_Context_Connect(hContext, NULL); 
 DBG(" Connect to TPM\n", result);
 // Get the TPM handle
 result=
 Tspi_Context_GetTpmObject(hContext, &hTPM); 
 DBG(" GetTPM Handle\n", result); 
  
 
 Tspi_Context_FreeMemory(hContext, NULL);
 Tspi_Context_Close(hContext);
 return 0;
}
