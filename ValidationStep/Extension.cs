using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VerifilerCore;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// Extension step checks file extensions and reports those that were not placed
	/// on the allowedExtensions whitelist via AddRestriction method. This step is skipped
	/// if no restrictions are set.
	/// </summary>
	internal class Extension : Step {

		private readonly HashSet<string> allowedExtensions = new HashSet<string>();
		public override int ErrorCode { get; set; } = Error.Extension;

		public void AddRestriction(string extension) {
			if (!extension.StartsWith(".")) {
				extension = '.' + extension;
			}
			allowedExtensions.Add(extension.ToLower());
		}

		public void RemoveRestriction(string extension) {
			if (!extension.StartsWith(".")) {
				extension = '.' + extension;
			}
			allowedExtensions.Remove(extension.ToLower());
		}

		public override void Setup() {

			Name = "File Extension Verification";
			if (allowedExtensions.Count > 0) {
				Enable();
			} else {
				Disable();
			}
		}

		public override void Run() {

			foreach (var file in Configuration.Instance.FileList) {
				var extension = Path.GetExtension(file);
				extension = extension?.ToLower();
				if (IsExtensionAllowed(extension)) {
					ReportAsValid(file);
				} else {
					ReportAsError(file, file + " has invalid extension. Actual: " + extension + "; Expected: " + WhitelistToString());
				}
			}
		}

		private bool IsExtensionAllowed(string extension) {
			return allowedExtensions.Contains(extension);
		}

		private string WhitelistToString() {
			return String.Join(", ", allowedExtensions.ToArray());
		}
	}
}
