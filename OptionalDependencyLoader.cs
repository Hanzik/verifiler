using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using NLog;
using VerifilerCore;

namespace Verifiler {

	internal class OptionalDependencyLoader {
		
		private readonly List<string> optionalLibraries;
		private readonly string path;

		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public OptionalDependencyLoader() {
			logger.Debug("Initializing OptionalDependencyLoader");

			path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar;
			optionalLibraries = new List<string>();
			optionalLibraries.Add("VerifilerACCDB.dll");
			optionalLibraries.Add("VerifilerImage.dll");
			optionalLibraries.Add("VerifilerMSLegacy.dll");
			optionalLibraries.Add("VerifilerODF.dll");
			optionalLibraries.Add("VerifilerOpenXML.dll");
			optionalLibraries.Add("VerifilerPDF.dll");
		}

		public List<Step> Load() {
			logger.Info("Loading optional dependencies");

			List<Step> optionalSteps = new List<Step>();

			foreach (var library in optionalLibraries) {
				logger.Info("Searching for {0}", library);

				try {
					var dll = Assembly.LoadFile(path + library);
					logger.Info("Library {0} found, loading all components", library);

					foreach (var type in dll.GetExportedTypes()) {
						logger.Debug("Loading {0}", type.FullName);
						dynamic instance = Activator.CreateInstance(type);
						optionalSteps.Add(instance);
					}
				} catch (FileNotFoundException e) {
					logger.Info("Library {0} was not found, it will not be loaded", library);
					continue;
				}
			}

			return optionalSteps;
		}
	}
}
