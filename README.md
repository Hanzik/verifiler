# Verifiler - File verification library

For when you need a thorough file inspection for your .NET projects.

### Features
  * Validate:
    * Size
    * Extension
    * File signature (magic number)
    * Checksum
  * Add your own custom validation step
  * Verify integrity of file (detect corrupted files)
  * Integrate your own Anti-Virus engine 


### How to use the library

Verifiler offers a variety of commands, all listed below on this page. It all boils down to three simple steps:

  1. Create an instance of **Verifiler.Inspector**
  2. Setup validation parameters (read list of available commands below)
  3. Start the scan by calling the **Scan(string path)** method

---
  
### Validating files (initiating the scan)
  
  * **Scan(string path)**

Must be an absolute path to the file or directory. If a .zip archive is passed, it will be extracted to temporary folder and treated as a directory.
  
```csharp          
string file = "C:\path\to\file.txt"

Inspector inspector = new Verifiler.Inspector();
Result res = inspector.MinSize(500).Scan(file);

Assert.AreEqual(VerifilerCore.Result.Ok, res.Code());
```

If a directory is passed to the Scan() method, all files inside will be validated.

```csharp  
string folder = "C:\path\to\directory"

Inspector = new Verifiler.Inspector();
Result res = Inspector.MinSize(500).Scan(folder);

Assert.AreEqual(VerifilerCore.Result.Ok, res.Code());
```

---

### Anti-Virus scan

  * **EnableAV(string pathToExecutable, string parameters)**                                           
  * **DisableAV()**

Run AntiVirus engine installed on your machine and scan the files before they are analyzed by Verifiler. Most of available AntiVirus engines
are packed with a console application, which is the application you are looking for. **DO NOT FORGET TO SET THE PARAMETERS CORRECTLY.**

In our example below, we are using AVAST Antivirus which has a console application called "ashCmd.exe" and we run it with 
parameters "C:\path\to\scanned\directory /_" which tell the application to scan our folder and print result to the standard output.
AV engines tend to offer similar options, but the parameters might be called differently or have different order. Look it up for the AV engine
you have installed.
  
**Example:**  
```csharp    
string pathToAV = "C:\Program Files\AVAST Software\Avast\ashCmd.exe";
string parameters = "C:\path\to\scanned\directory /_";
inspector.EnableAV(pathToAV, parameters)
         .Scan("C:\path\to\scanned\directory");
```

---

### VirusTotal

  * **EnableVirusTotal(string apiKey)**
  * **DisableVirusTotal()**

Sends the files to [VirusTotal](https://www.virustotal.com/) and reports files with **Error.Fatal** if at least 10% of AV engines find
the file suspicious. Should any of the files be found guilty, the scan process will terminate.

You can get your own VirusTotal API key by registering on their website and going to your profile page. Keep in mind that public API keys
allow only for 4 files per minute to be scanned for malware via their service.
  
**Example:**  
```csharp     
string apiKey = "3e53db1820ed111d4f5ba77c54535aaf92608464be164d2b5";
inspector.EnableVirusTotal(apiKey);
```

---

### Checksum whitelist

  * **AddAllowedChecksum(string md5checksum)**
  * **RemoveAllowedChecksum(string md5checksum)**
  * **AddAllowedChecksums(string[] md5checksums)**
  * **RemoveAllowedChecksums(string[] md5checksums)**

Add or remove MD5 file checksum from the whitelist. If the whitelist is empty, this step will be skipped. If it is not empty,
files whose checksum is not on the whitelist will be reported with Error.Checksum.

**Example:**
```csharp   
inspector = inspector.AddAllowedChecksum("B7C3B2E6A048869FD039BE423620C212")
                    .AddAllowedChecksum("AC87ASDH9012AC9FD939EG423620C012")
                    .AddAllowedChecksum("PQOEU87AS8869ZD039BE423620C662");
```

---

### File extension

  * **AddExtensionRestrictions(string[] types)**
  * **AddExtensionRestriction(string type)**
  * **RemoveExtensionRestrictions(string[] types)**
  * **RemoveExtensionRestriction(string type)**

Similar to checksum whitelist. Add or remove extensions from whitelist. If the whitelist is empty, this step will be skipped. If it is not empty,
files whose extension is not on the whitelist will be reported with Error.Extension.

**Example:** 
```csharp  
string[] allowedTypes = { ".txt", ".html", ".jpg", ".png" };
inspector = inspector.AddExtensionRestrictions(allowedTypes)
                    .AddExtensionRestriction(".gif")
                    .RemoveExtensionRestriction(".jpg");
```

---

### File size

  * **MinSize(int kilobytes)**
  * **MaxSize(int kilobytes)**

Setup a minimum and/or maximum size in kilobytes of scanned files. Files who break this rule will be reported with **Error.Size**.

**Example:** 
```csharp  
inspector = inspector.MinSize(256).MaxSize(1024);
```

---

### File signature

  * **EnableSignatureTest()**
  * **DisableSignatureTest()**

Compares file's extension with file's magic number located in their header. Database of signatures was taken 
from [File Signatures database](https://www.filesignatures.net/). Files who break this rule will be reported with **Error.Signature**.

**Example:** 
```csharp  
inspector = inspector.EnableSignatureTest();
```

---

### File integrity verification
 
  * **EnableFormatVerification()**
  * **DisableFormatVerification()**

Enables verifications of file's integrity. This requires for some of the optional packages to be installed (depending on which extensions you want to verify).
Look at the [list of available packages](#list-of-optional-verification-libraries).

**Example:** 
```csharp   
inspector = inspector.EnableFormatVerification();             
```

---

### Custom validation step

  * **AddCustomStep(Step step)**
  * **RemoveAllCustomSteps()**

You can add your own validation steps. In the example below, we create a validation step which checks the name of every file and let's though only those
that start with string "abc". This means that "abctextfile.txt" will pass, but "defimage.jpg" will not. Failed tests will return Error.Generic or if you
override the ErrorCode, it can return whatever code you want (as shown in the example). It is preffered if such error is a positive integer.

**Example:** 
```csharp  
inspector.AddCustomStep(new StartsWithStep("abc")).Scan(GetTestFolderPath());

class StartsWithStep : VerifilerCore.Step {

	private readonly string startString;
	
	public override int ErrorCode { get; set; } = VerifilerCore.Error.Generic;

	public StartsWithStep(string startString) {
		this.startString = startString;
		Enable();
	}

	public override void Run() {
		foreach (var file in GetListOfFiles()) {
			string name = Path.GetFileName(file);
			if (name.StartsWith(startString)) {
				ReportAsValid(file);
			} else {
				ReportAsError(file, name + " doesn't start with " + startString);
			}
		}
	}
}
```

---

## List of optional verification libraries

You can install the following libraries (via NuGet) if you want to detect files which
may have been corrupted during transfer (or any other reason).

  * **VerifilerACCDB** ([GitHub](https://github.com/Hanzik/verifiler-accdb) | [NuGet](https://www.nuget.org/packages/VerifilerACCDB/)) - .accdb 
  * **VerifilerImage** ([GitHub](https://github.com/Hanzik/verifiler-image) | [NuGet](https://www.nuget.org/packages/VerifilerImage/)) - .jpg, .png
  * **VerifilerMSLegacy** ([GitHub](https://github.com/Hanzik/verifiler-mslegacy) | [NuGet](https://www.nuget.org/packages/VerifilerMSLegacy/)) - .xls 
  * **VerifilerODF** ([GitHub](https://github.com/Hanzik/verifiler-odf) | [NuGet](https://www.nuget.org/packages/VerifilerODF/)) - .ods, .odt
  * **VerifilerOpenXML** ([GitHub](https://github.com/Hanzik/verifiler-openxml) | [NuGet](https://www.nuget.org/packages/VerifilerOpenXML/)) - .docx, .pptx, .xlsx
  * **VerifilerPDF** ([GitHub](https://github.com/Hanzik/verifiler-pdf) | [NuGet](https://www.nuget.org/packages/VerifilerPDF/)) - .pdf


## List of other relevant repositories

  * **VerifilerCore** ([GitHub](https://github.com/Hanzik/verifiler-core) | [NuGet](https://www.nuget.org/packages/VerifilerCore/)) - Core library containing classes required by all other Verifiler libraries.
  * **VerifilerTest** ([GitHub](https://github.com/Hanzik/verifiler-test)) - Unit test library.
