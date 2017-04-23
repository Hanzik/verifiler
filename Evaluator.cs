using NLog;
using VerifilerCore;

namespace Verifiler {

	/// <summary>
	/// If all steps finished successfuly, Result.Ok is returned. If one of the steps failed,
	/// it will return the error code of this step and if there were more errors, the Error.Multiple
	/// will be returned instead.
	/// </summary>
	class Evaluator {
		
		private int response;

		private static Logger logger = LogManager.GetCurrentClassLogger();

		public Evaluator() {
			response = Result.Ok;
		}

		public void StepEvaluation(int code) {
			logger.Debug("Retrieving total evaluation");
			if (response != Result.Ok && code != Result.Ok) {
				response = Error.Multiple;
			} else if (code != Result.Ok) {
				response = code;
			}
		}

		/// <summary>
		/// If all steps finished successfuly, Result.Ok is returned. If one of the steps failed,
		/// it will return the error code of this step and if there were more errors, the Error.Multiple
		/// will be returned instead.
		/// </summary>
		/// <returns>
		///   <c>Result.Ok</c> if all steps returned Result.Ok
		///   <c>Error.Multiple</c> if more steps failed with an error
		///   <c>Specific error code</c> if one step failed with its designated error code
		/// </returns>
		public int ScanEvaluation() {
			return response;
		}
	}
}
