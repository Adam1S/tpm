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
 TSS_HENCDATA hEncData;

 BYTE napis[]="Trudno wierzyc, ze to dziala";
 UINT32		ulDataLength=sizeof(napis);

/////////////////////////////////////

BYTE *prgbDataToUnBind;
UINT32 pulDataLength;

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

 result=Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
								TSS_ENCDATA_BIND, &hEncData);
 DBG("create encdata object", result);
 
 result=Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
								TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
								TSS_ES_RSAESPKCSV15);
 DBG("set attrib uint32", result);

 result=Tspi_Data_Bind(hEncData, hKey, ulDataLength, napis);
 DBG("Binded!", result);

 printf("\n\n\n%x\n", &hEncData);
 printf("To bind napisu %s\n\n", napis);
 
 if ((fp=fopen("binded_data.txt", "w"))==NULL) {
       printf ("Nie mogę otworzyć pliku binded_data.txt do zapisu!\n");
       exit(1);
    }
  fprintf (fp, "%x", hEncData ); /* zapisz nasz łańcuch w pliku */
  fclose (fp); /* zamknij plik */


 result = Tspi_Data_Unbind(hEncData, hKey, &pulDataLength,
				  &prgbDataToUnBind);
 DBG("unbinded ", result);
 printf("\n\nUnbided data: %s", prgbDataToUnBind);
 return 0;
}
