using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using VerifilerCore;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// Checksum step computes MD5 checksum for every file and reports those that were not placed
	/// on the allowedChecksums whitelist via AddAllowedChecksum method. This step is skipped
	/// if the whitelist is empty.
	/// </summary>
	internal class Checksum : Step {

		private readonly HashSet<string> allowedChecksums = new HashSet<string>();
		public override int ErrorCode { get; set; } = Error.Checksum;

		public void AddAllowedChecksum(string checksum) {
			allowedChecksums.Add(checksum);
		}

		public void RemoveAllowedChecksum(string checksum) {
			allowedChecksums.Remove(checksum);
		}

		public override void Setup() {

			Name = "MD5 Checksum Verification";
			if (allowedChecksums.Count > 0) {
				Enable();
			} else {
				Disable();
			}
		}

		public override void Run() {
			foreach (var file in Configuration.Instance.FileList) {
				var tuple = IsFileChecksumAllowed(file);
				var isFileAllowed = tuple.Item1;
				var fileChecksum = tuple.Item2;
				if (isFileAllowed) {
					ReportAsValid(file);
				} else {
					ReportAsError(file, file + " has disallowed MD5 checksum. Actual: " + fileChecksum + "; Expected: " + WhitelistToString());
				}
			}
		}

		private Tuple<bool, string> IsFileChecksumAllowed(string file) {
			using (var md5 = MD5.Create()) {
				using (var stream = File.OpenRead(file)) {
					var checksum = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "‌​").ToLower();
					return Tuple.Create(allowedChecksums.Contains(checksum), checksum);
				}
			}
		}

		private string WhitelistToString() {
			return string.Join(", ", allowedChecksums.ToArray());
		}
	}
}
