using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Xml.Serialization;
using NLog;
using VerifilerCore;

namespace Verifiler.ValidationStep {

	/// <summary>
	/// Signature step reads first few bytes of given file and checks if these bytes,
	/// so called file signatures, match the type of the file. Bytes read from the file
	/// are compared to preset values given via template file (Resources/signatures.xml by
	/// default).
	/// </summary>
	internal class Signature : Step {

		private readonly Dictionary<string, List<int[]>> signatures = new Dictionary<string, List<int[]>>();
		public override int ErrorCode { get; set; } = Error.Signature;
		private static Logger logger = LogManager.GetCurrentClassLogger();

		public Signature() {

			var path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), @"Resources\signatures.xml");
			var serializer = new XmlSerializer(typeof(FileExtension[]), new XmlRootAttribute() { ElementName = "FileExtensions" });
			
			var extensions = (FileExtension[])serializer.Deserialize(File.OpenRead(path));
			foreach (var fe in extensions) {
				var ext = fe.Extension.ToLower();
				if (!signatures.ContainsKey(ext)) {
					signatures[ext] = new List<int[]>();
				}
				signatures[ext].Add(fe.GetArrayFromSignature());
			}
		}

		public override void Setup() {
			Name = "File Signature Verification";
		}

		public override void Run() {

			foreach (var file in Configuration.Instance.FileList) {
				var extension = Path.GetExtension(file);
				if (IsExtensionValid(file)) {
					ReportAsValid(file);
				} else {
					ReportAsError(file, file + " has invalid signature. Expected: " + String.Join(",", signatures[extension]));
				}
			}
		}

		private bool IsExtensionValid(string file) {

			var extension = Path.GetExtension(file).ToLower();
			if (!signatures.ContainsKey(extension)) {
				logger.Warn("Extension {0} has no known signatures in our database. Signature test will be skipped for this file.", extension);
				return true;
			}
			var acceptedSignatures = signatures[extension];

			FileStream stream = File.Open(file, FileMode.Open);
			var signature = new byte[20];
			stream.Read(signature, 0, 20);
			stream.Close();

			foreach (var acceptedSignature in acceptedSignatures) {

				for (int i = 0; i < acceptedSignature.Length; i++) {
					if (signature[i] != acceptedSignature[i]) {
						break;
					}
					if (i == acceptedSignature.Length - 1) {
						return true;
					}
				}
			}

			return false;
		}
	}

	[Serializable()]
	public class FileExtension {
		
		[System.Xml.Serialization.XmlAttribute("extension")]
		public string Extension { get; set; }

		[System.Xml.Serialization.XmlAttribute("signature")]
		public string Signature { get; set; }

		public int[] GetArrayFromSignature() {

			string[] split = Signature.Split(' ');
			int[] signatureArray = new int[split.Length];
			int index = 0;
			foreach (String hex in split) {
				signatureArray[index++] = Convert.ToInt32(hex, 16);
			}

			return signatureArray;
		}
	}
}
