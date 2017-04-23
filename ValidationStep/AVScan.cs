using System;
using System.Diagnostics;
using NLog;
using VerifilerCore;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// Runs the installed AV engine against scanned files. Since AV engines can vary,
	/// user must provide location of the executable and parameters which the executable
	/// should be run with. This can be done via Inspector.EnableAV(...) method.
	/// </summary>
	internal class AVScan : Step {

		public string AvLocation { get; set; }
		public string AvParameters { get; set; }

		public override int ErrorCode { get; set; } = Error.Fatal;

		private static Logger logger = LogManager.GetCurrentClassLogger();

		public override void Setup() {
			Name = "Antivirus scan";
			FatalErrorEncountered = false;
		}

		public override void Run() {

			logger.Info("Starting up the AV engine located at '{0}' with parameters '{1}'", AvLocation, AvParameters);

			ProcessStartInfo processInfo = new ProcessStartInfo();
			processInfo.FileName = AvLocation;
			processInfo.Arguments = AvParameters;
			processInfo.CreateNoWindow = true;
			processInfo.UseShellExecute = false;
			processInfo.RedirectStandardOutput = true;
			processInfo.WindowStyle = ProcessWindowStyle.Hidden;

			try {
				using (Process exeProcess = Process.Start(processInfo)) {
					while (!exeProcess.StandardOutput.EndOfStream) {
						Console.WriteLine(exeProcess.StandardOutput.ReadLine());
					}
					logger.Info("Waiting for AV scan to finish");
					exeProcess.WaitForExit();
					if (exeProcess.ExitCode != 0) {
						FatalErrorEncountered = true;
						ReportAsError("AV Scan detected virus in scanned files. Aborting.");
					} else {
						ReportAsValid();
					}
				}
			} catch(Exception ex) {
				logger.Error("There was an error while running the AV engine");
				Console.WriteLine(ex.Message);
			}
		}
	}
}
