using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Serialization;
using NLog;
using Verifiler.ValidationStep;
using VerifilerCore;

namespace Verifiler {

	internal class OptionalDependencyLoader {

		private readonly List<Library> optionalLibraries = new List<Library>();
		private readonly string path;
		
		public Dictionary<string, Library> LibraryMapping { get; set; }

		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public OptionalDependencyLoader() {
			logger.Debug("Initializing OptionalDependencyLoader");

			path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + Path.DirectorySeparatorChar;

			var xmlpath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
				@"Resources\libraries.xml");
			var serializer = new XmlSerializer(typeof(Library[]), new XmlRootAttribute() {ElementName = "Libraries"});
			var libraries = (Library[]) serializer.Deserialize(File.OpenRead(xmlpath));

			LibraryMapping = new Dictionary<string, Library>();
			foreach (var lib in libraries) {
				optionalLibraries.Add(lib);
				foreach (var extension in lib.Extensions.Split(' ')) {
					LibraryMapping[extension] = lib;
				}
			}
		}

		public List<FormatSpecificValidator> Load() {
			logger.Info("Loading optional dependencies");

			var optionalSteps = new List<FormatSpecificValidator>();

			foreach (var library in optionalLibraries) {
				logger.Info("Searching for {0}", library.Name);

				try {
					var dll = Assembly.LoadFile(path + library.Name + ".dll");
					logger.Info("Library {0} found, loading all components", library.Name);

					foreach (var type in dll.GetExportedTypes()) {
						logger.Debug("Loading {0}", type.FullName);
						dynamic instance = Activator.CreateInstance(type);
						optionalSteps.Add(instance);
					}
					library.Loaded = true;
				} catch (FileNotFoundException) {
					logger.Info("Library {0} was not found, it will not be loaded", library.Name);
					continue;
				}
			}

			return optionalSteps;
		}

		internal List<string> GetLoadedLibraries() {
			var list = new List<string>();
			foreach (var library in optionalLibraries) {
				if (library.Loaded) {
					list.Add(library.Name);
				}
			}
			return list;
		}

		internal bool IsLibraryLoaded(string libraryName) {
			libraryName = libraryName.EndsWith(".dll") ? libraryName.Replace(".dll", "") : libraryName;
			foreach (var library in optionalLibraries) {
				if (library.Name != libraryName) {
					continue;
				}
				return library.Loaded;
			}
			return false;
		}

		internal bool IsFormatSupported(string format) {
			format = format.StartsWith(".") ? format : "." + format;
			return LibraryMapping.ContainsKey(format);
		}

		internal bool IsFormatValidatorLoaded(string format) {
			format = format.StartsWith(".") ? format : "." + format;
			if (LibraryMapping.ContainsKey(format)) {
				return LibraryMapping[format].Loaded;
			}
			return false;
		}

		internal List<string> GetListOfSupportedFormats() {
			return LibraryMapping.Keys.ToList();
		}
	}

	[Serializable()]
	public class Library {
		
		[System.Xml.Serialization.XmlAttribute("extensions")]
		public string Extensions { get; set; }

		[System.Xml.Serialization.XmlAttribute("name")]
		public string Name { get; set; }

		public bool Loaded { get; set; }
	}
}
