using System;
using System.IO;
using NLog;
using VerifilerCore;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// Size step checks if file is within set bounds. These bounds are set with
	/// MinSize and MaxSize variable. If one or both of these values are not set,
	/// the constraint is ignored.
	/// </summary>
	internal class Size : Step {

		public int MinSize { get; set; }
		public int MaxSize { get; set; }

		private bool validateMinSize;
		private bool validateMaxSize;
		private long minSizeBytes;
		private long maxSizeBytes;

		private static Logger logger = LogManager.GetCurrentClassLogger();

		public override int ErrorCode { get; set; } = Error.Size;

		private const int ToBytesConversion = 1024;
		
		public override void Setup() {

			Name = "File Size Verification";

			if (MinSize == 0 && MaxSize == 0) {
				Disable();
				return;
			}
			
			validateMinSize = MinSize > 0;
			validateMaxSize = MaxSize > 0;
			minSizeBytes = MinSize * ToBytesConversion;
			maxSizeBytes = MaxSize * ToBytesConversion;

			Enable();
		}

		public override void Run() {
			foreach (var file in Configuration.Instance.FileList) {
				Tuple<bool, long> fileInspection = IsFileValid(file);
				bool fileValid = fileInspection.Item1;
				long fileSize = fileInspection.Item2;

				if (fileValid) {
					ReportAsValid(file);
				} else {
					string interval = "<" + minSizeBytes + "; " + (MaxSize > 0 ? maxSizeBytes.ToString() : "Inf") + ">";
					ReportAsError(file, "File " + file + " has invalid size. Actual: " + fileSize + " - Allowed range: " + interval);
				}
			}
		}

		private Tuple<bool, long> IsFileValid(string path) {

			var info = new FileInfo(path);
			if (validateMinSize && info.Length < minSizeBytes) {
				return Tuple.Create(false, info.Length);
			}
			if (validateMaxSize && info.Length > maxSizeBytes) {
				return Tuple.Create(false, info.Length);
			}
			return Tuple.Create(true, info.Length);
		}
	}
}
