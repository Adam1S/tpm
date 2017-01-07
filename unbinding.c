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
 FILE *fp;

 TSS_HCONTEXT	hContext;
 TSS_HTPM	hTPM;
 TSS_RESULT	result;
 TSS_HKEY	hSRK=0;
 TSS_HPOLICY	hSRKPolicy=0, hKeyPolicy=0;
 TSS_UUID	SRK_UUID=TSS_UUID_SRK;
 BYTE		wks[20]; //for the well known secret
 TSS_UUID	keyUUID={1,2,3,4,5,6,7,8,9,10,2};
 TSS_HKEY	hKey=0;
 TSS_HENCDATA hEncData, hAnotherData;

 BYTE		napis[]="Trudno wierzyc, ze to dziala";
 BYTE		*out;
 UINT32		outSize;
 UINT32		ulDataLength=sizeof(napis);

 BYTE		*unbind_data_buf;
 UINT32		unbind_data_size;

/////////////////////////////////////

BYTE *prgbDataToUnBind;
UINT32 pulDataLength;

BYTE *bind_data_buf;
UINT32 bind_data_size;

/////////////////////////////////////

 memset(wks,0,20);


 result=Tspi_Context_Create(&hContext);
 DBG("Create Context",result);

 result=Tspi_Context_Connect(hContext, NULL);
 DBG("Conntect Context", result);


 result=Tspi_Context_GetTpmObject(hContext,
				&hTPM);
 DBG("Get tpm obj", result); 
/////////////////////////////////////////////////////////////////////////////////
 result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
							SRK_UUID, &hSRK);
 DBG("Load SRK Key", result);

 result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hSRKPolicy );
 DBG("Get SRK Policy", result);

 result=Tspi_Policy_SetSecret(hSRKPolicy, TSS_SECRET_MODE_SHA1,20,wks);
 DBG("Set SRK secret", result);

/////////////////////////////////////////////////////////////////////////////////

 result=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
							keyUUID, &hKey);
 DBG("Load Binding Key", result);
	
 result=Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyPolicy);
 DBG("Load Binding Key Policy", result);

 result=Tspi_Policy_SetSecret(hKeyPolicy, TSS_SECRET_MODE_SHA1,20,wks);
 DBG("Set Binding Policy secret", result);
//////////////////////////////////////////////////////////////////////////////////

 if ((fp=fopen("binded_data.txt", "w"))==NULL) {
       printf ("Nie mogę otworzyć pliku binded_data.txt do zapisu!\n");
       exit(1);
    }
  fread(out,1,4,fp);
  fclose (fp); /* zamknij plik */

 result=Tspi_Data_Unbind(out, hKey, &unbind_data_size, &unbind_data_buf);
 DBG("Try", result);
 
 return 0;
}
