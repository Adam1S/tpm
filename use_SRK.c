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
 TSS_HPOLICY	hSRKPolicy=0;
 TSS_UUID	SRK_UUID=TSS_UUID_SRK;
 BYTE		wks[2]; //for the well known secret

 memset(wks,0,20);

 result=Tspi_Context_Create(&hContext);
 DBG("Create Context",result);

 result=Tspi_Context_Connect(hContext, NULL);

 if ( result != TSS_SUCCESS )
 {
  DBG( "Tspi_Context_Create", result );
  exit( result );
 }
 
 result=Tspi_Context_GetTpmObject(hContext,
				&hTPM);
 DBG("Get tpm obj", result); 

 return 0;
}
