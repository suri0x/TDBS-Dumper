## TDBS Dumper - TriangleDB iOS Spyware String Dumper
TDBS Dumper is a simple python script which can identify, dump, and decrypt protected strings from the TriangleDB iOS spyware implant. 
A special thanks to the Kaspersky team for their analysis series:  https://securelist.com/trng-2023/ <br>
Sample: https://bazaar.abuse.ch/sample/fd9e97cfb55f9cfb5d3e1388f712edd952d902f23a583826ebe55e9e322f730f/

### TDBS Dumper Usage 
Usage: `python3 tdbs.py <binary_path>`<br>
Example: `python3 tdbs.py fd9e97cfb55f9cfb5d3e1388f712edd952d902f23a583826ebe55e9e322f730f.macho`

## Context
TriangleDB (Operation Triangulation) was an iOS spyware campaign conducted by an unknown APT (at least publicly unknown) that targeted the Russia-based cybersecurity company, Kaspersky. TriangleDB utilized four iOS zero-days for its deployment onto iOS devices. Below is a graphic of the full attack chain provided by Kaspersky. TDBS Dumper specifically focuses on the final stage spyware implant.

![image](https://github.com/suri0x/TDBS-Dumper/assets/95584654/a685082e-1c58-4eab-9956-601f63ccf612)


As mentioned above, the TDBS Dumper aids in identifying, dumping, and decrypting protected strings from the TriangleDB iOS spyware implant. TriangleDB's spyware implant utilizes basic HEX-encoded, rolling XOR-encrypted strings, which are employed in certain Objective-C methods and functions within the implant. Below is a compiled list of the methods in question.

```
-[CRAInfo retrieveIADict] - Utilized in the implant ability to enumerate all applications on the mobile device.
      Collected Application Details:
          - applicationType  - shortVersionString
          - vendorName       - bundleContainerURL
          - path             - bundleIdentifier
          - bundleURL        - containerURL
          - dataContainerURL - localizedName
          - groupContainerURLs

-[CRConfig spinUp] - Utilized by the implant for WIFI related functions. It's refrencing the iOS WIFI manager.
      Utilized WIFI manager functions:
          - WiFiManagerClientCreate  - WiFiManagerClientCopyDevices
          - WiFiNetworkGetSSID       - WiFiNetworkGetProperty
          - WiFiDeviceClientCopyCurrentNetwork

-[CRConfig populateWithSysInfo] - Utilized to get system information to send back heartbeats to C2.
      Examples of system information:
           - UDID  - IMEI
           - MEID  - EID
           - OS Version

-[CRConfig init] - Initialization of the implant configuration.

-[CRConfig getBuildArchitecture] - Self explanatory

-[CRGetIndexesV2 execute] - Seems to be related to executing SQLite queries against the iOS keychain db.
      Example strings found:
           - SELECT data FROM %@
           - SELECT keyclass, actualKeyclass, data FROM metadatakeys
           - /private/var/Keychains/keychain-2.db
```

Moving on to the protected strings within the implant. Kaspersky provided a cleaned up version on the function used to unprotect the strings. See below:
```
id +[CRConfig unmungeHexString:](id a1, SEL a2, id stringToDecrypt) {
  // code omitted
  while (1) {
	hexByte[0] = stringBytes[i];
	hexByte[1] = stringBytes[i + 1];
	encryptedByte = strtoul(hexByte, &__endptr, 16);
	if (__endptr == hexByte) 
          break;
	i += 2LL;
	if (j)
  	    decryptedString[j] = encryptedByte ^ previousByte;
	else
  	    decryptedString[0] = encryptedByte;
	++j;
	previousByte = encryptedByte;
	if (i >= stringLength) 
          break;
  }
  decryptedString[j] = 0;
  // code omitted
}
```
I've provided some examples below of how this is actually called within the implants code:

![image](https://github.com/suri0x/TDBS-Dumper/assets/95584654/8da7f1bd-d0e9-4878-90d6-4d71cd7fe644)


![image](https://github.com/suri0x/Icarus/assets/95584654/b14ebc7e-710d-49e9-993a-b4222670a2fc)


