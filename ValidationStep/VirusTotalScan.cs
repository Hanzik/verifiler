using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using NLog;
using VerifilerCore;
using VirusTotalNET;
using VirusTotalNET.Objects;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// When enabled, this step sends scanned files to VirusTotal via API they provide.
	/// API key must be provided for this step to work. VirusTotal public API is fairly
	/// limited in number of requests per minute (and per day), which makes it suitable
	/// only for scanning few files.
	///
	/// VirusTotal runs scanned files through many different AV engines and returns list
	/// detailing which of them found each of the files suspicious.
	///
	/// More information: https://www.virustotal.com/cs/documentation/public-api/
	/// </summary>
	internal class VirusTotalScan : Step {

		public string ApiKey { get; set; }

		private VirusTotal virusTotal;
		private List<FileReport> reports;
		private const int VirusTotalQuota = 4;

		public override int ErrorCode { get; set; } = Error.VirusTotal;
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public override void Setup() {
			Name = "Virus Total scan";

			if (ApiKey == null) {
				Disable();
				return;
			}

			if (Configuration.Instance.FileList.Count > VirusTotalQuota) {
				Disable();
				logger.Warn("Virus Total scan can not be used for this run as the tested folder contains more files ({0} files) than your Virus Total request rate allows (typically {1}).", Configuration.Instance.FileList.Count, (VirusTotalQuota - 1));
				return;
			}
			
			virusTotal = new VirusTotal(ApiKey);
			virusTotal.UseTLS = true;
			Enable();
		}

		public override void Run() {

			reports = new List<FileReport>();
			foreach (var path in Configuration.Instance.FileList) {

				/* Skip directories */
				var attributes = File.GetAttributes(path);
				if ((attributes & FileAttributes.Directory) == FileAttributes.Directory) {
					continue;
				}

				try {
					var result = SendFileToVirusTotalAsync(path).Result;
					reports.Add(result);
				} catch (AggregateException ex) {
					/* Thrown when request limit reached. Abort step when this happens. */
					logger.Error("API request limit reached, VirusTotal scan will be aborted. Upgrade your API key or lower the amount of files tested. {0}", ex.Message);
					StepAborted = true;
					return;
				}
			}
			
			foreach (var report in reports) {
				
				if (Configuration.Instance.OutputType == Const.OutputVerbose) {
					logger.Debug("Scan ID: {0}", report.ScanId);
					logger.Debug("Message: {0}", report.VerboseMsg);
				}

				if (report.ResponseCode != ReportResponseCode.Present) {
					continue;
				}
				
				var positive = 0.0;
				foreach (KeyValuePair<string, ScanEngine> scan in report.Scans) {
					if (scan.Value.Detected) {
						positive++;
					}
					if (Configuration.Instance.OutputType == Const.OutputVerbose) {
						logger.Debug("{0,-20} Detected: {1}", scan.Key, scan.Value.Detected);
					}
				}

				/* How many AV engines must find the file suspicious to report this as an error (0 - none, 1 - all). */
				var alertThreshold = 0.1;
				if (positive / reports.Count > alertThreshold) {
					FatalErrorEncountered = true;
					ReportAsError(report.Resource, "VirusTotal's AV engines rank file " + report.Resource + " as suspicious.");
				} else {
					ReportAsValid(report.Resource);
				}
			}
		}

		private async Task<FileReport> SendFileToVirusTotalAsync(string path) {
			var result = await virusTotal.GetFileReport(new FileInfo(path));
			return result;
		}
	}
}
