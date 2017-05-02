using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using NLog;
using Verifiler.ValidationStep;
using VerifilerCore;

namespace Verifiler {

	/// <summary>
	/// Main class which library users directly use. The interface provided
	/// by Inspector allows users to enable/disable many different steps the library
	/// offers. When the user is done setting up the library, the scan can be
	/// started via Scan() method.
	/// </summary>
	public class Inspector {

		private Result result;

		private readonly List<Step> stepsList = new List<Step>();
		private readonly List<Step> customStepsList = new List<Step>();
		private readonly List<Step> formatSpecificList = new List<Step>();

		private readonly AVScan stepAvScan;
		private readonly Extension stepExtension;
		private readonly Checksum stepChecksum;
		private readonly Signature stepSignature;
		private readonly Size stepSize;
		private readonly VirusTotalScan stepVirusTotalScan;

		private readonly OptionalDependencyLoader loader;
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public Inspector() {
			logger.Info("Initializing Inspector instance");

			stepAvScan = new AVScan();
			stepExtension = new Extension();
			stepChecksum = new Checksum();
			stepSignature = new Signature();
			stepSize = new Size();
			stepVirusTotalScan = new VirusTotalScan();
			
			stepsList.Add(stepExtension);
			stepsList.Add(stepChecksum);
			stepsList.Add(stepSignature);
			stepsList.Add(stepSize);
			
			Console.WriteLine("Loading optional dependencies");
			loader = new OptionalDependencyLoader();
			foreach (var validator in loader.Load()) {
				formatSpecificList.Add(validator);
			}
		}

		/// <summary>
		/// Before files are scanned by all the verification methods, they will
		/// first be checked by provided AV engine.
		/// </summary>
		/// <param name="pathToExecutable"> Absolute path to the AV engine executable.</param>
		/// <param name="parameters"> Parameters with which the AV engine should be run. This must include
		/// the parameter that scans the folder which contains scanned files (eg. "-folder C:\Path\To\Folder" or whatever
		/// your AV engine supports). You can include other parameters suchs as the option to export logs from the AV scan
		/// to file (should your AV engine support this option).</param>
		public Inspector EnableAV(string pathToExecutable, string parameters) {
			logger.Info("Enabling Anti-Virus engine scan with path: {0}, parameters: {1}", pathToExecutable, parameters);
			stepAvScan.AvLocation = pathToExecutable;
			stepAvScan.AvParameters = parameters;
			stepAvScan.Enable();
			return this;
		}

		public Inspector DisableAV() {
			logger.Info("Disabling Anti-Virus engine scan");
			stepAvScan.Disable();
			return this;
		}

		/// <summary>
		/// Sends scanned files to VirusTotal for their evaluation.
		/// </summary>
		/// <param name="apiKey"> Your API key registered with VirusTotal service. Keep in mind that their public API
		/// they provide for free have very limited number of files you can scan per minute (usually 4), so this will not
		/// work if you plan on scanning more than few files.</param>
		public Inspector EnableVirusTotal(string apiKey) {
			logger.Info("Enabling VirusTotal scan with API key: {0}", apiKey);
			stepVirusTotalScan.ApiKey = apiKey;
			return this;
		}

		public Inspector DisableVirusTotal() {
			logger.Info("Disabling VirusTotal scan");
			stepVirusTotalScan.ApiKey = null;
			return this;
		}

		/// <summary>
		/// Adds passed extensions to whitelist of allowed file types.
		/// </summary>
		/// <param name="types">Array of file types to be added to the whitelist (example: {.exe, php, jpg, .png}).</param>
		public Inspector AddExtensionRestrictions(string[] types) {
			foreach (var type in types) {
				stepExtension.AddRestriction(type);
			}
			return this;
		}

		/// <summary>
		/// Adds checksum to whitelist of allowed file checksums. If the checksum whitelist is empty,
		/// this step will be skipped.
		/// </summary>
		/// <param name="checksum">MD5 checksum of file to be placed on the checksum whitelist.</param>
		public Inspector AddAllowedChecksum(string checksum) {
			logger.Info("Adding the following checksum on whitelist: {0}", checksum);
			stepChecksum.AddAllowedChecksum(checksum);
			return this;
		}

		/// <summary>
		/// Removes checksum from whitelist of allowed file checksums. If the checksum whitelist is empty,
		/// this step will be skipped.
		/// </summary>
		/// <param name="checksum">MD5 checksum of file to be removed from the checksum whitelist.</param>
		public Inspector RemoveAllowedChecksum(string checksum) {
			logger.Info("Removing the following checksum from whitelist: {0}", checksum);
			stepChecksum.RemoveAllowedChecksum(checksum);
			return this;
		}

		/// <summary>
		/// Adds checksums to whitelist of allowed file checksums. If the checksum whitelist is empty,
		/// this step will be skipped.
		/// </summary>
		/// <param name="checksums">Array of MD5 checksums of files to be placed on the checksum whitelist.</param>
		public Inspector AddAllowedChecksums(string[] checksums) {
			foreach (var checksum in checksums) {
				stepChecksum.AddAllowedChecksum(checksum);
			}
			return this;
		}

		/// <summary>
		/// Removes checksums from whitelist of allowed file checksums. If the checksum whitelist is empty,
		/// this step will be skipped.
		/// </summary>
		/// <param name="checksums">Array of MD5 checksum of file to be removed from the checksum whitelist.</param>
		public Inspector RemoveAllowedChecksums(string[] checksums) {
			foreach (var checksum in checksums) {
				stepChecksum.RemoveAllowedChecksum(checksum);
			}
			return this;
		}

		/// <summary>
		/// Adds extension to whitelist of allowed file types.
		/// </summary>
		/// <param name="type">File type to be added to the whitelist (example: .doc).</param>
		public Inspector AddExtensionRestriction(string type) {
			logger.Info("Adding the following extension on whitelist: {0}", type);
			stepExtension.AddRestriction(type);
			return this;
		}

		/// <summary>
		/// Removes extension from whitelist of allowed file types. Should some of the extensions not exist
		/// in the whitelist, they will be ignored.
		/// </summary>
		/// <param name="types">Array of file types to be removed from the whitelist (example: {.exe, php, jpg, .png}).</param>
		public Inspector RemoveExtensionRestrictions(string[] types) {
			foreach (var type in types) {
				stepExtension.RemoveRestriction(type);
			}
			return this;
		}

		/// <summary>
		/// Removes extension from whitelist of allowed file types. Should the extension not exist
		/// in the whitelist, this will be ignored.
		/// </summary>
		/// <param name="type">File type to be removed from the whitelist (example: .doc).</param>
		public Inspector RemoveExtensionRestriction(string type) {
			logger.Info("Removing the following extension from whitelist: {0}", type);
			stepExtension.RemoveRestriction(type);
			return this;
		}

		/// <summary>
		/// Files with less than minimum allowed size will not pass the verification step. 
		/// </summary>
		/// <param name="kilobytes">Minimum allowed size in kilobytes.</param>
		public Inspector MinSize(int kilobytes) {
			logger.Info("Setting the minimum allowed size (in kilobytes) for files: {0}", kilobytes);
			stepSize.MinSize = kilobytes;
			return this;
		}

		/// <summary>
		/// Files with more than maximum allowed size will not pass the verification step. 
		/// </summary>
		/// <param name="kilobytes">Maximum allowed size in kilobytes.</param>
		public Inspector MaxSize(int kilobytes) {
			logger.Info("Setting the maximum allowed size (in kilobytes) for files: {0}", kilobytes);
			stepSize.MaxSize = kilobytes;
			return this;
		}

		/// <summary>
		/// Enables test that verifies if file's signature (magic numbers in file's headers) correspond
		/// to the extension the file has. Example: If file's extension is .jpg, this step will check that
		/// the file contains one of .jpg's known signatures.
		/// 
		/// All known signatures are saved in signatures.xml file in Resources.
		/// </summary>
		public Inspector EnableSignatureTest() {
			logger.Info("Enabling file signature test");
			stepSignature.Enable();
			return this;
		}

		/// <summary>
		/// Disables file signature verification.
		/// </summary>
		public Inspector DisableSignatureTest() {
			logger.Info("Disabling file signature test");
			stepSignature.Disable();
			return this;
		}

		/// <summary>
		/// Allows users to add custom verification step. Must extend VerificationStep.Step class and implement
		/// methods Setup(), Run() and Cleanup(). Custom steps are run after all the default steps.
		/// </summary>
		public Inspector AddCustomStep(Step step) {
			logger.Info("Adding custom validation step: {0}", step.Name);
			customStepsList.Add(step);
			return this;
		}

		/// <summary>
		/// Removes all custom steps added via the AddCustomStep(Step) method.
		/// </summary>
		public Inspector RemoveAllCustomSteps() {
			logger.Info("Removing all custom steps");
			customStepsList.Clear();
			return this;
		}

		/// <summary>
		/// Enables format specific verifications which test, whether files are corrupted or whether they can be
		/// opened. This requires optional libraries installed (e.g. VerifilePDF, VerifileImage, VerifileOpenXML).
		/// 
		/// You can do this via NuGet package manager (e.g. "Install-Package VerifilePDF"). To find out which extensions
		/// are supported, visit library's page on GitHub.
		/// </summary>
		public Inspector EnableFormatVerification() {
			logger.Info("Enabling format specific verifications");
			Configuration.Instance.FormatSpecificEnabled = true;
			return this;
		}

		/// <summary>
		/// Disables format specific verifications.
		/// </summary>
		public Inspector DisableFormatVerification() {
			logger.Info("Disabling format specific verifications");
			Configuration.Instance.FormatSpecificEnabled = false;
			return this;
		}

		/// <summary>
		/// Return list of library names which were correctly loaded.
		/// </summary>
		/// <returns>
		///   <c>List</c> of libraries which were correctly loaded and will be used during the Scan()
		/// </returns>
		public List<string> GetLoadedLibraries() {
			return loader.GetLoadedLibraries();
		}

		/// <summary>
		/// Find out what formats are supported by one of the Verifiler libraries. This method will
		/// return list of extensions which have a verification library available.
		/// </summary>
		/// <returns>
		///   <c>List</c> of formats which have a Verifiler library available via NuGet or GitHub.
		/// </returns>
		public List<string> GetListOfSupportedFormats() {
			return loader.GetListOfSupportedFormats();
		}

		/// <summary>
		/// Use this method to find out if optional library for your specific format was correctly loaded
		/// and whether such file's integrity will be verified by the format specific validator.
		/// </summary>
		/// <param name="libraryName">Library name (eg. "VerifilerOpenXML", "VerifilerPDF").</param>
		/// <returns>
		///   <c>TRUE</c> if library was correctly loaded
		/// </returns>
		public bool IsLibraryLoaded(string libraryName) {
			return loader.IsLibraryLoaded(libraryName);
		}

		/// <summary>
		/// Use this method to find out if specified format is supported by one of the verification
		/// libraries in the Verifiler bundle.
		/// </summary>
		/// <param name="format">Library name (eg. ".pdf", ".xlsx", ".jpg").</param>
		/// <returns>
		///   <c>TRUE</c> if library for this format exists and can be downloaded via GitHub or NuGet
		/// </returns>
		public bool IsFormatSupported(string format) {
			return loader.IsFormatSupported(format);
		}

		/// <summary>
		/// Use this method to find out if optional library for your specific format was correctly loaded
		/// and whether such file's integrity will be verified by the format specific validator.
		/// </summary>
		/// <param name="format">File format (eg. ".jpg", ".doc", ".pdf").</param>
		/// <returns>
		///   <c>TRUE</c> if specified format will be validated (FormatSpecific validations must be enabled
		/// via EnableFormatVerification() method.
		/// </returns>
		public bool IsFormatValidated(string format) {
			return loader.IsFormatValidatorLoaded(format);
		}

		/// <summary>
		/// Based on previous settings, the library runs all enabled verification steps.
		/// </summary>
		/// <returns>
		///   <c>Const.ResponseOK</c> if all steps returned ResponseOK
		///   <c>Const.ResponseWarning</c> if at least one step returned ResponseWarning
		///   <c>Const.ResponseError</c> if at least one step returned Response Error
		///   <c>Const.ResponseFatalError</c> if fatal error preventing further verification steps from running, such as AV engine flagging scanned files as infected.
		/// </returns>
		public Result Scan(string path) {
			logger.Info("Initiating scan of {0}", path);

			var evaluator = new Evaluator();
			result = new Result();

			Configuration.Instance.ScanPath = path;
			int preparationResponse = Configuration.Instance.Prepare();
			if (preparationResponse != Result.Ok) {
				result.SetResponseCode(preparationResponse);
				return result;
			}

			/* We initially mark all files as valid. */
			result.SetFilesValid(Configuration.Instance.FileList);

			/* If AV step is enabled, run it first. If it fails, abort scan. */
			stepAvScan.Setup();
			if (stepAvScan.Enabled()) {
				RunStep(stepAvScan);
				if (stepAvScan.FatalErrorEncountered) {
					logger.Warn("Anti-Virus scan detected a malware in one of the files. Aborting.");
					Cleanup();
					result.SetResponseCode(Error.Fatal);
					return result;
				}
			}

			/* If VirusTotal scan step is enabled, run it first. If it fails, abort scan. */
			stepVirusTotalScan.Setup();
			if (stepVirusTotalScan.Enabled()) {
				RunStep(stepVirusTotalScan);
				if (stepVirusTotalScan.FatalErrorEncountered) {
					logger.Warn("VirusTotal scan detected a malware in one of the files. Aborting.");
					Cleanup();
					result.SetResponseCode(Error.Fatal);
					return result;
				}
			}

			/* First run default steps, abort if FatalError is encountered. Run custom steps after.*/
			logger.Debug("Initiating generic file validations");
			var genericStepsResult = RunStepsFromList(stepsList, evaluator);
			if (genericStepsResult != Error.Fatal) {
				logger.Debug("Initiating custom file validations");
				var customStepsResult = RunStepsFromList(customStepsList, evaluator);
				if (customStepsResult != Error.Fatal && Configuration.Instance.FormatSpecificEnabled) {
					logger.Debug("Initiating format specific file verifications");
					RunStepsFromList(formatSpecificList, evaluator);
				}
			}

			Cleanup();
			result.SetResponseCode(evaluator.ScanEvaluation());
			return result;
		}

		private int RunStep(Step step) {
			logger.Debug("Initiating step {0}", step.Name);
			step.Run();
			result.AddExecutedStep(stepAvScan.Name);
			//result.SetFilesInvalid(step.InvalidFilesList, step.ErrorCode);
			return step.Summary();
		}

		private int RunStepsFromList(List<Step> list, Evaluator evaluator) {

			foreach (var step in list) {
				step.Setup();
				if (step.Enabled()) {
					var stepResult = RunStep(step);
					evaluator.StepEvaluation(stepResult);
				}
			}
			return Result.Ok;
		}

		private void Cleanup() {
			logger.Info("Cleaning up started.");
			Configuration.Instance.Cleanup();
			foreach (var step in stepsList) {
				step.Cleanup();
			}
			foreach (var step in customStepsList) {
				step.Cleanup();
			}
		}
	}
}
