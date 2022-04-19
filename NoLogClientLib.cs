using System;
using System.Text;
using System.Collections.Generic;
using io.nolog.net.api.auth;
using io.nolog.net.api.writespec;
using System.Net.Http;
using System.IO;
using System.IO.Compression;

namespace nolog
{
  namespace internals {
    class utils {
      internal static bool has_bit(int bits, error_bit bit) {
        return (bits & (int)bit) > 0;
      }
      internal static bool has_bit(int bits, notify_bit bit) {
        return (bits & (int)bit) > 0;
      }
      internal static int with_bit(int bits, error_bit bit) {
        return bits | (int)bit;
      }
      internal static int with_bit(int bits, notify_bit bit) {
        return bits | (int)bit;
      }

      internal static string trim(string field, int length, bool cleanse)
      {
        if (field == null)
        {
          return "UNKNOWN";
        }
        if (cleanse)
        {
          var newField = new StringBuilder();
          var validChars = "ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz1234567890/.";
          foreach (char c in field.ToCharArray())
          {
            if (!validChars.Contains(c))
            {
              continue;
            }
            newField.Append(c);
          }
          field = newField.ToString().ToLower();
        }
        if (field.Length == 0)
        {
          return "UNKNOWN";
        }
        if (field.Length > length)
        {
          field = field.Substring(0, length - 3) + "...";
        }
        return field;
      }
    }

    enum error_bit {
      ERROR_BIT_DO_NOT_USE = 0,
      ERROR_BIT_MULTIPLE_INITIALIZATION = 1,
      ERROR_BIT_CLOSING_CLOSED_TRACKER = 2,
      ERROR_BIT_OPEN_CHILD_OF_CLOSED_TRACKER = 4,
      ERROR_BIT_CLOSING_TRACKED_AFTER_PARENT = 8,
      ERROR_BIT_USED_UNREGISTERED_ALERT = 16,
      ERROR_BIT_DUPLICATE_OBJECTIVE = 32,
      ERROR_BIT_DUPLICATE_DEPENDENCY = 64,
      ERROR_BIT_GC_BEFORE_CLOSING = 128,
      ERROR_BIT_EMPTY_API_KEY = 256,
      ERROR_BIT_INVALID_API_KEY = 512,
      ERROR_BIT_MISSING_DEPENDENCY_TO_START_DEP = 1024,
      ERROR_BIT_USED_UNREGISTERED_DEPENDENCY = 2048,
      ERROR_BIT_USED_ALERT_DOUBLE_REGISTERED = 4096
    }

    enum notify_bit {
      NOTIFY_BIT_DO_NOT_USE = 0,
      NOTIFY_BIT_SERVICE_ID_MISSING = 1,
      NOTIFY_BIT_INSTANCE_ID_MISSING = 2,
      NOTIFY_BIT_FORGOT_TO_INITIALIZE = 4,
      NOTIFY_BIT_EMPTY_API_KEY = 8,
      NOTIFY_BIT_INVALID_API_KEY = 16
    }

    class errorhandler {
      private List<string> errors = new List<string>();
      private int error_bits = 0;
      private int notify_bits = 0;

      internal Tuple<int, List<string>> safe_get_errors() {
        lock(this) {
          return new Tuple<int, List<string>>(error_bits, new List<string>(this.errors));
        }
      }

      internal void safe_add_error(string err, error_bit bit) {
        if (bit == error_bit.ERROR_BIT_DO_NOT_USE) {
          throw new ArgumentException("Found invalid error bit: ERROR_BIT_DO_NOT_USE");
        }
        lock(this) {
          if (utils.has_bit(error_bits, bit)) {
            return;
          }
          error_bits = utils.with_bit(error_bits, bit);
          errors.Add(err);
        }
      }

      internal void safe_notify(string notification, notify_bit bit) {
        if (bit == notify_bit.NOTIFY_BIT_DO_NOT_USE) {
          throw new ArgumentException("Found invalid error bit: ERROR_BIT_DO_NOT_USE");
        }
        lock(this) {
          if (utils.has_bit(notify_bits, bit)) {
            return;
          }
          notify_bits = utils.with_bit(notify_bits, bit);
        }
        Console.WriteLine(notification);
      }

      internal bool safe_has_error() {
        lock(this) {
          return error_bits > 0;
        }
      }
    }

    class alert {
      private int count = 0;
      private List<string> samples = new List<string>();
      private int last_count = 0;
      private List<string> last_samples = new List<string>(); 
      private int invocation_count = 0;
      private long last_timestamp = 0;
      private base_counter parent;
      public string core_alert;
      private int max_invocation_count;

      internal alert(string core_alert, int max_invocation_count, base_counter parent)
      {
        this.parent = parent;
        this.core_alert = internals.utils.trim(core_alert, 200, false);
        this.max_invocation_count = max_invocation_count;
      }

      internal bool safe_with_context(base_counter caller, string context) {
        if (caller != parent) {
          return false;
        }
        if (context == null) {
          context = "";
        }
        lock(this) {
          int count = this.count;
          this.count++;
          if (count < 300 && count % 100 == 0) {

            context = internals.utils.trim(context, 1000, false);
            samples.Add(context);
          }
        }
        return true;
      }

      internal Tuple<bool, List<String>, int, long> safe_sample_alerts() {
        lock(this) {
          if (this.invocation_count == 0 && this.count == 0) {
            return new Tuple<bool, List<String>, int, long>(false, null, 0, 0);
          }
          if (this.invocation_count == 0) {
            this.last_samples = this.samples;
            this.last_count = this.count;
            this.last_timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
          }
          this.invocation_count = (this.invocation_count + 1)%this.max_invocation_count;
          List<String> last_samples = new List<string>(this.last_samples);
          return new Tuple<bool, List<String>, int, long>(true, last_samples, last_count, last_timestamp);
        }
      }
    }

    class base_counter {
      public string name;
      public string action;
      private bool nolog_init = false;
      private int failure_window;
      private int successful = 0;
      private int failing = 0;
      private LinkedList<int> success_history = new LinkedList<int>();
      private LinkedList<int> failing_history = new LinkedList<int>();
      public errorhandler errors;
      public base_counter parent = null;
      private Dictionary<string, base_counter> children = new Dictionary<string, base_counter>();
      private Dictionary<string, alert> alerts = new Dictionary<string, alert>();

      internal base_counter(string name, bool nolog_init, int failure_window, base_counter parent=null, string action="") {
        this.name = name;
        this.action = action;
        this.nolog_init = nolog_init;
        this.failure_window = failure_window;
        this.parent = parent;
        if (parent != null)
        {
          this.errors = parent.errors;
        }
        else
        {
          this.errors = new errorhandler();
        }
      }

      internal alert safe_with_alert(string core_alert, int max_invocation_count) {
        lock (this)
        {
          if (alerts.ContainsKey(core_alert))
          {
            return null;
          }
          alert a = new alert(core_alert, max_invocation_count, this);
          alerts.Add(core_alert, a);
          return a;
        }
      }

      internal Tuple<bool, int, int, ICollection<base_counter>, List<alert>> proto_data() {
        lock(this) {
          int successful = this.successful;
          int failing = this.failing;
          success_history.AddLast(successful);
          failing_history.AddLast(failing);
          this.successful = 0;
          this.failing = 0;
          while (success_history.Count > failure_window) {
            success_history.RemoveFirst();
            failing_history.RemoveFirst();
          }
          bool success = true;
          foreach (int failed in failing_history) {
            if (failed > 0) {
              success = false;
              break;
            }
          } 
          return new Tuple<bool, int, int, ICollection<base_counter>, List<alert>>(
            success, successful, failing, new List<base_counter>(children.Values), new List<alert>(alerts.Values));
        }
      }

      internal base_counter safe_add_child(string name, string action, int failure_window) {
        string key = name+":"+action;
        lock(this) {
          base_counter child;
          if (children.TryGetValue(key, out child)) {
            errors.safe_add_error(
              "Called AddDependency multiple times with same name:action ("+key+")",
              error_bit.ERROR_BIT_DUPLICATE_DEPENDENCY);
            return child;
          }
          child = new base_counter(name, nolog_init, failure_window, this, action);
          children.Add(key, child);
          return child;
        }
      }

      internal void safe_update_init(bool is_initialized) {
        List<base_counter> children;
        lock(this) {
          nolog_init = is_initialized;
          children = new List<base_counter>(this.children.Values); 
        }
        foreach (base_counter child in children) {
          child.safe_update_init(is_initialized);
        }
      }

      internal void safe_increment(int inc_success, int inc_fail) {
        lock(this) {
          successful+=inc_success;
          failing+=inc_fail;
        }
      }

      internal tracker safe_start() {
        lock(this) {
          if (!nolog_init) {
            errors.safe_notify(
              "Did you forget to Initialize NoLog? Found "+name+".start() call before nolog.Initialize()",
              notify_bit.NOTIFY_BIT_FORGOT_TO_INITIALIZE
            );
            return tracker.disabled_tracker;
          }
        }
        return new tracker(this);
      }
    }

    class tracker {
      static internal tracker disabled_tracker = new tracker(null, true);

      private bool disabled = false;
      private bool parent_closed = false;
      private bool closed = false;
      private base_counter parent;
      private LinkedList<tracker> children = new LinkedList<tracker>();
  
      internal tracker(base_counter parent, bool disabled = false) {
        if (disabled) {
          this.disabled = disabled;
          return;
        }
        this.parent = parent;
      }

      internal void safe_parent_closed() {
        lock(this) {
          parent_closed = true;
          bool closed = this.closed;
        }
        if (!closed) {
          parent.errors.safe_add_error(
              "Bad Monitoring State: Objective Tracker closed before DependencyTracker.",
              error_bit.ERROR_BIT_OPEN_CHILD_OF_CLOSED_TRACKER);
        }
      }

      internal void unsafe_close_children() {
        foreach (tracker child in children) {
          child.safe_parent_closed();
        }
        children.Clear();
      }

      internal void safe_success() {
        if (disabled) {
          return;
        }
        lock(this) {
          unsafe_close_children();
          if (closed) {
            parent.errors.safe_add_error(
              "Bad Monitoring State: Tracker closed twice, success() called on closed Tracker.",
              error_bit.ERROR_BIT_CLOSING_CLOSED_TRACKER);
            return;
          }
          closed = true;
          if (parent_closed) {
            parent.errors.safe_add_error(
              "Bad Monitoring State: Tried to close DependencyTracker after closing ObjectiveTracker.",
              error_bit.ERROR_BIT_CLOSING_TRACKED_AFTER_PARENT);
            return;
          }
        }
        parent.safe_increment(1, 0);
      }

      internal void safe_fail(alert a, string context) {
        if (disabled) {
          return;
        }
        lock(this) {
          unsafe_close_children();
          if (closed) {
            parent.errors.safe_add_error(
              "Bad Monitoring State: Tracker closed twice, success() called on closed Tracker.",
              error_bit.ERROR_BIT_CLOSING_CLOSED_TRACKER);
            return;
          }
          closed = true;
          if (parent_closed) {
            parent.errors.safe_add_error(
              "Bad Monitoring State: Tried to close DependencyTracker after closing ObjectiveTracker.",
              error_bit.ERROR_BIT_CLOSING_TRACKED_AFTER_PARENT);
            return;
          }
        }
        parent.safe_increment(0, 1);
        if (a != null) {
          if (!a.safe_with_context(parent, context)) {
            parent.errors.safe_add_error(
              "Tried to fail() with unregistered Alert: " + a.core_alert,
              error_bit.ERROR_BIT_USED_UNREGISTERED_ALERT);
          }
        }
      }

      internal tracker safe_start(base_counter parent) {
        if (disabled) {
          return this;
        }
        if (this.parent != parent.parent)
        {
          parent.errors.safe_add_error(
            "Tried to start tracking an unregistered Dependency for Objective.",
            error_bit.ERROR_BIT_USED_UNREGISTERED_DEPENDENCY);
          return tracker.disabled_tracker;
        }
        tracker t = new tracker(parent);
        lock(this) {
          children.AddLast(t);
        }
        return t;
      }

      ~tracker() {
        if (disabled) {
          return;
        }
        unsafe_close_children();
        if (!this.closed) {
          parent.errors.safe_add_error(
            "Tracker garbage collected before closing. Did you forget to success()/fail()?",
            error_bit.ERROR_BIT_GC_BEFORE_CLOSING);
        }
      }
    }
  }

  /// <summary>
  /// Predefined message to surface in the event of a failure when fulfilling an Objective or calling a Dependency.
  /// </summary>
  public class Alert {
    internal internals.alert alert;
    internal Alert(internals.alert a) {
      this.alert = a;
    }
  }

  /// <summary>
  /// Dependency tracks out-of-process entities (e.g. other services, databases, or agents) that an Objective relies on.
  /// </summary>
  public class Dependency {
    internal internals.base_counter bc;
    internal Dependency(internals.base_counter parent) {
      this.bc = parent;
    }

    /// <summary>
    // Statically define alerts (max: 200 chars) expected to be triggered when facing problems with this Dependency.
    // Objective metadata is automatically added to the Alert and does not need to be included in the
    // actual alert message.
    /// </summary>
    public Alert WithAlert(string alert) {
      internals.alert a = bc.safe_with_alert(alert, 3);
      if (a == null)
      {
        this.bc.errors.safe_add_error(
          "Alert " + alert + " declared twice.",
          internals.error_bit.ERROR_BIT_USED_ALERT_DOUBLE_REGISTERED);
        return new Alert(null);
      }
      return new Alert(a);
    }
  }

  /// <summary>
  /// Dependency measures the success rate of calling a dependency and helps trigger alrets in the event of a failure.
  /// </summary>
  public class DependencyTracker {
    private internals.tracker tracker;

    internal DependencyTracker(internals.tracker tracker) {
      this.tracker = tracker;
    }

    /// <summary>
    /// Success is used to mark this tracker as successfully completed (including ending early due to bad input or reaching successful completion).
    /// Calling Success() or Fail(...) marks this tracker as closed.
    /// Forgetting to close or trying to re-close a tracker results in tracking entering an error state.
    /// </summary>
    public void Success() {
      this.tracker.safe_success();
    }

    /// <summary>
    /// Fail is used to mark the tracker as failed using the Alert as the reason.
    /// Included error messages (max: 1000 chars) passed to Fail() will be sampled
	  /// before being sent onwards.
    /// Calling Success() or Fail(...) marks this tracker as closed.
    /// Forgetting to close or trying to re-close a tracker results in tracking entering an error state.
    /// </summary>
    public void Fail(Alert alert, string errorMsg) {
      tracker.safe_fail(alert != null ? alert.alert : null, errorMsg);
    }
  }

  /// <summary>
  /// ObjectiveTracker tracks a single fulfillment of a given Objective.
  /// </summary>
  public class ObjectiveTracker {
    private internals.tracker tracker;

    internal ObjectiveTracker(internals.tracker tracker) {
      this.tracker = tracker;
    }

    /// <summary>
    /// Success is used to mark this tracker as successfully completed (including ending early due to bad input or reaching successful completion).
    /// Calling Success() or Fail(...) marks this tracker as closed.
    /// Forgetting to close or trying to re-close a tracker results in tracking entering an error state.
    /// </summary>
    public void Success() {
      this.tracker.safe_success();
    }

    /// <summary>
    /// Fail is used to mark the tracker as failed using the Alert as the reason.
    /// Included error messages (max: 1000 chars) passed to Fail() will be sampled
	  /// before being sent onwards.
    /// Calling Success() or Fail(...) marks this tracker as closed.
    /// Forgetting to close or trying to re-close a tracker results in tracking entering an error state.
    /// </summary>
    public void Fail(Alert alert, string errorMsg) {
      tracker.safe_fail(alert != null ? alert.alert : null, errorMsg);
    }

    /// <summary>
  	/// Begin tracking the invocation of a dependency.
    /// </summary>
    public DependencyTracker StartDependency(Dependency dep) {
      if (dep == null) {
        return new DependencyTracker(internals.tracker.disabled_tracker);
      }
      return new DependencyTracker(tracker.safe_start(dep.bc));
    }
  }

  /// <summary>
  /// Objective represents a monitored service goal.
  /// Each service goal is registered once via a nolog.CreateObjective or nolog.DefineObjective and an
  /// Objective is returned to be used in code for monitoring.
  /// </summary>
  public class Objective {
    internal internals.base_counter bc;
    internal Objective(internals.base_counter bc) {
      this.bc = bc;
    }

    /// <summary>
	  /// Add a Dependency (max: 40 chars) to track that is used by this Objective and a short action (max: 40 chars) that describes the usage.
    /// </summary>
    public Dependency AddDependency(string name, string action) {
      name = internals.utils.trim(name, 40, true);
      action = internals.utils.trim(action, 40, true);
      internals.base_counter dep_counter = bc.safe_add_child(name, action, 6);
      return new Dependency(dep_counter);
    }

    /// <summary>
    // Statically define alerts (max: 200 chars) expected to be triggered when facing problems with this Dependency.
    // Objective and Dependency metadata is automatically added to the Alert and does not need to be included in the
    // actual alert message.
    /// </summary>
    public Alert WithAlert(string alert) {
      internals.alert a = bc.safe_with_alert(alert, 3);
      if (a == null)
      {
        this.bc.errors.safe_add_error(
          "Alert " + alert + " declared twice.",
          internals.error_bit.ERROR_BIT_USED_ALERT_DOUBLE_REGISTERED);
        return new Alert(null);
      }
      return new Alert(a);
    }

    /// <summary>
    /// Start tracking the fulfillment of this objective.
    /// </summary>
    public ObjectiveTracker Start() {
      return new ObjectiveTracker(bc.safe_start());
    }
  }

  class NoLog {
    enum env_bit {
      STD,
      LOCAL,
      PERFORMANCE,
      PRODUCTION
    }

    private const string reserved_block_name = "NoLogDefault";
    static bool initialized = false;
    static Dictionary<string, Objective> objectives = new Dictionary<string, Objective>();
    static internals.errorhandler errors = new internals.errorhandler();
    static string service_id = "";
    static string instance_id = "";
    static string version_id = "";
    static string raw_key = "";
    static ClientKey key = null;
    static env_bit env = env_bit.STD;
    static string target = "";
    static string shard = "0";
    static string shard_token = "init";

    private static void start_reporting()
    {
      byte[] b = new byte[4];
      System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(b);
      int r = 0;
      BitConverter.ToInt32(b, r);
      r %= 2000;
      System.Threading.Thread.Sleep(r);
      long lastExec = DateTimeOffset.Now.ToUnixTimeSeconds();
      while (true)
      {
        long now = DateTimeOffset.Now.ToUnixTimeSeconds();
        while (now - lastExec < 10)
        {
          System.Threading.Thread.Sleep(1000);
          now = DateTimeOffset.Now.ToUnixTimeSeconds();
        }
        lastExec = now;
        report();
      }
    }

    private static void report(){
      if (NoLog.errors.safe_has_error()) {
        return;
      }
      List<Objective> objectives;
      WriteRequest w = new WriteRequest()
      {
        Ids = new ServiceInstanceIdentifier()
        {
          ServiceId = service_id,
          InstanceId = instance_id,
          VersionId = version_id
        },
        CreationTimestamp = new Timestamp()
      };
      lock(NoLog.reserved_block_name) {
        w.CreationTimestamp.UtcCreationTime = DateTimeOffset.Now.ToUnixTimeSeconds();
        w.RawInformation = new WriteRequest.Types.RawInformation();
        objectives = new List<Objective>(NoLog.objectives.Values);
      }
      foreach (var obj in objectives) {
        Tuple<bool, int, int, ICollection<internals.base_counter>, List<internals.alert>> obj_data = obj.bc.proto_data();
        var critical_block = new WriteRequest.Types.RawInformation.Types.CriticalBlock()
        {
          Name = obj.bc.name,
          Counts = new WriteRequest.Types.RawInformation.Types.Counts()
          {
            Success = obj_data.Item2,
            Failed = obj_data.Item3
          },
          State = obj_data.Item1 ? State.AllOk : State.CriticalFailure
        };
        Tuple<int, List<string>> obj_error_data = obj.bc.errors.safe_get_errors();
        if (obj_error_data.Item1 > 0) {
          AlertInformation alert_info = new AlertInformation()
          {
            CoreAlert = "Objective misconfigured.",
            TotalCount = obj_error_data.Item2.Count,
            Timestamp = DateTimeOffset.Now.ToUnixTimeSeconds()
          };
          foreach (var err in obj_error_data.Item2) {
            alert_info.SampledContent.Add(err);
            if (alert_info.SampledContent.Count == 3)
            {
              break;
            }
          }
          critical_block.Alerts.Add(alert_info);
        } else {
          foreach (var dep in obj_data.Item4) {
            Tuple<bool, int, int, ICollection<internals.base_counter>, List<internals.alert>> dep_data = dep.proto_data();
            var block_dep = new WriteRequest.Types.RawInformation.Types.CriticalBlock.Types.BlockDependency()
            {
              Dependency = dep.name,
              Action = dep.action,
              Counts = new WriteRequest.Types.RawInformation.Types.Counts()
              {
                Success = obj_data.Item2,
                Failed = obj_data.Item3
              },
              State = dep_data.Item1 ? State.AllOk : State.CriticalFailure
            };
            if (!dep_data.Item1 && critical_block.State != State.AllOk) {
              critical_block.State = State.DependencyFailure;
            }
            foreach (var alert in dep_data.Item5)
            {
              Tuple<bool, List<string>, int, long> alert_data = alert.safe_sample_alerts();
              if (!alert_data.Item1) {
                continue;
              }
              var alert_info = new AlertInformation()
              {

                Timestamp = alert_data.Item4,
                CoreAlert = alert.core_alert,
                TotalCount = alert_data.Item3,
              };
              alert_info.SampledContent.AddRange(alert_data.Item2);
              block_dep.Alerts.Add(alert_info);
            }
            critical_block.BlockDependency.Add(block_dep);
          }
          foreach (var alert in obj_data.Item5)
          {
            Tuple<bool, List<string>, int, long> alert_data = alert.safe_sample_alerts();
            if (!alert_data.Item1) {
              continue;
            }
            var alert_info = new AlertInformation()
            {

              Timestamp = alert_data.Item4,
              CoreAlert = alert.core_alert,
              TotalCount = alert_data.Item3,
            };
            alert_info.SampledContent.AddRange(alert_data.Item2);
            critical_block.Alerts.Add(alert_info);
          }
        }
        w.RawInformation.Blocks.Add(critical_block);
      }
      if (w.RawInformation.Blocks.Count == 0) {
        var no_data_block = new WriteRequest.Types.RawInformation.Types.CriticalBlock()
        {
          Name = NoLog.reserved_block_name,
          State = State.NoData
        };
        w.RawInformation.Blocks.Add(no_data_block);
      }
      NoLog.write_report_with_retry(w, 0);
    }

    enum retry_status_code {
      ALL_GOOD,
      RETRY,
      BAD
    }
    private static string[] lbs = new string[] { "alpha", "omega" };
    private static void write_report_with_retry(WriteRequest w, int attempt=0, System.Security.Cryptography.RandomNumberGenerator rng = null) {
      if (attempt >=2) {
        return;
      }
      if (w == null) {
        throw new Exception("This should never happen, tried to __write_report_with_retry with nil data.");
      }
      if (write_report(w, lbs[attempt % lbs.Length]) == retry_status_code.RETRY)
      {
        if (rng == null) {
          rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        } 
        byte[] b = new byte[4];
        rng.GetBytes(b);
        int r = 0;
        BitConverter.ToInt32(b, r);
        r %= 2000;
        write_report_with_retry(w, attempt+1, rng);
      }
    }

    private static HttpClient http_client = new HttpClient();
    private static retry_status_code write_report(WriteRequest w, string lb)
    {
      if (env == env_bit.STD) {
        Console.WriteLine(w);
        return retry_status_code.ALL_GOOD;
      }
      w.ShardInfo = new WriteRequest.Types.ShardInfo();
      w.ShardInfo.ShardToken = shard_token;
      string target = NoLog.target;
      if (env == env_bit.PERFORMANCE)
      {
        target = String.Format(target, shard);
      }
      else if (env == env_bit.PRODUCTION)
      {
        target = String.Format(target, lb, shard);
      }
      WriteResponse rrPb;
      try
      {
        string basic_token = "Basic " + raw_key;
        var message = new HttpRequestMessage(HttpMethod.Post, target);
        message.Headers.Add("Authorization", basic_token);
        var protoBytes = Google.Protobuf.MessageExtensions.ToByteArray(w);
        using (var cpBytes = new MemoryStream()) {
          using (var gzipStream = new GZipStream(cpBytes, CompressionMode.Compress)) {
            using (var mStream = new MemoryStream(protoBytes)) {
              mStream.CopyTo(gzipStream);
            }
          }
          message.Content = new ByteArrayContent(cpBytes.ToArray());
        }
        var aresponse = http_client.SendAsync(message, HttpCompletionOption.ResponseContentRead);
        aresponse.Wait();
        var response = aresponse.GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
          Console.WriteLine(response.StatusCode);
          byte[] error_content_bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
          Console.WriteLine(BitConverter.ToString(error_content_bytes));
          return retry_status_code.RETRY;
        }
        byte[] content_bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        rrPb = WriteResponse.Parser.ParseFrom(content_bytes);
      }
      catch
      {
        return retry_status_code.RETRY;
      }
      if (rrPb != null && rrPb.WriteStatus != null &&
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyCannotDecrypt ||
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyCannotUnbase64 ||
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyCannotUnmarshal ||
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyExpired ||
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyMissingField ||
        rrPb.WriteStatus.StatusCode == WriteResponseCode.Types.StatusCode.FailureApikeyInvalid) {
        return retry_status_code.BAD;
      }
      if (rrPb.Ok)
      {
        return retry_status_code.ALL_GOOD;
      }
      if (rrPb.UpdateShard != null)
      {
        int test_shard_num = 0;
        if (!int.TryParse(rrPb.UpdateShard.Shard, out test_shard_num) || test_shard_num < 0)
        {
          shard = rrPb.UpdateShard.Shard;
          shard_token = rrPb.UpdateShard.ShardToken;
        }
        else
        {
          shard = "0";
          shard_token = "cshnonnumeric";
        }
      }
      return retry_status_code.RETRY;
    }

    /// <summary>Initialize needs to be called in Main() before the program begins monitoring with NoLog.</summary>
    public static void Initialize(string service_id, string instance_id, string version_id, string noLogApiKey) {
      if (noLogApiKey != null && noLogApiKey.Length > 5000) {
        noLogApiKey = noLogApiKey.Substring(0, 5000);
      }
      lock(reserved_block_name) {
        if (initialized) {
          errors.safe_add_error(
          "nolog.Initialize() should only be called once.",
          internals.error_bit.ERROR_BIT_MULTIPLE_INITIALIZATION);
          return;
        }
        if (noLogApiKey == null || noLogApiKey.Length == 0) {
          errors.safe_notify(
            "Cannot initialize NoLog with empty key",
            internals.notify_bit.NOTIFY_BIT_EMPTY_API_KEY);
          errors.safe_add_error(
            "Cannot initialize NoLog with empty key",
            internals.error_bit.ERROR_BIT_EMPTY_API_KEY);
          return;
        }
        if (service_id == null || service_id.Length == 0){
          errors.safe_notify(
            "ServiceID is missing.",
            internals.notify_bit.NOTIFY_BIT_SERVICE_ID_MISSING);
          return;
        }
        if (instance_id == null || instance_id.Length == 0){
          errors.safe_notify(
            "InstanceID is missing.",
            internals.notify_bit.NOTIFY_BIT_INSTANCE_ID_MISSING);
          return;
        }
        NoLog.service_id = internals.utils.trim(service_id, 40, true);
        NoLog.instance_id = internals.utils.trim(instance_id, 40, true);
        NoLog.version_id = internals.utils.trim(version_id, 10, true);
        initialized = true;
        foreach (Objective obj in objectives.Values) {
          obj.bc.safe_update_init(initialized);
        }
        raw_key = noLogApiKey;
        if (!noLogApiKey.Equals("local")) {
          try {
            key = ClientKey.Parser.ParseFrom(System.Convert.FromBase64String(noLogApiKey));
          } catch(Exception) {
            errors.safe_notify(
              "Cannot initialize NoLog with invalid API key",
              internals.notify_bit.NOTIFY_BIT_INVALID_API_KEY);
            errors.safe_add_error(
              "Cannot initialize NoLog with invalid API key",
              internals.error_bit.ERROR_BIT_INVALID_API_KEY);
            return;
          }
          Dictionary<string, env_bit> envs = new Dictionary<string, env_bit>();
          envs.Add("LOCAL", env_bit.LOCAL);
          envs.Add("PERFORMANCE", env_bit.PERFORMANCE);
          envs.Add("PRODUCTION", env_bit.PRODUCTION);
          Dictionary<env_bit, string> targets = new Dictionary<env_bit, string>();
          targets.Add(env_bit.LOCAL, "http://localhost:8080/be/write");
          targets.Add(env_bit.PERFORMANCE, "http://performance.nolog.io/writer%s/be/write");
          targets.Add(env_bit.PRODUCTION, "https://%s.nolog.io/writer%s/be/write");
          bool env_found = false;
          foreach (string k in key.KeyFields.Keys) {
            if (k.Equals("n")) {
              if (!envs.TryGetValue(key.KeyFields[k], out env)) {
                errors.safe_notify(
                  "Cannot initialize NoLog with invalid API key",
                  internals.notify_bit.NOTIFY_BIT_INVALID_API_KEY);
                errors.safe_add_error(
                  "Cannot initialize NoLog with invalid API key",
                  internals.error_bit.ERROR_BIT_INVALID_API_KEY);
                return;
              }
              NoLog.target = targets[env];
              env_found = true;
              break;
            }
          }
          if (!env_found) {
            errors.safe_notify(
              "Cannot initialize NoLog with invalid API key",
              internals.notify_bit.NOTIFY_BIT_INVALID_API_KEY);
            errors.safe_add_error(
              "Cannot initialize NoLog with invalid API key",
              internals.error_bit.ERROR_BIT_INVALID_API_KEY);
            return;
          }
        }
        System.Threading.Thread report_thread = new System.Threading.Thread(new System.Threading.ThreadStart(NoLog.start_reporting));
        report_thread.IsBackground = true;
        report_thread.Start();
      }
    }

    /// <summary>
    /// CreateObjective (max: 40 chars) returns an ObjectiveTracker used for monitoring a Service objective.
    /// </summary>
    public static Objective CreateObjective(string name) {
      name = internals.utils.trim(name, 40, true);
      if (name.StartsWith("nolog")) {
        name = "custom." + name;
      }
      lock(reserved_block_name) {
        Objective existingObj;
        if (objectives.TryGetValue(name, out existingObj)) {
          existingObj.bc.errors.safe_add_error(
            "Called CreateObjective multiple times with same 'name'. Disabling tracking of Objective.",
            internals.error_bit.ERROR_BIT_DUPLICATE_OBJECTIVE);
          return existingObj;
        }
        Objective obj = new Objective(new internals.base_counter(name, initialized, 6));
        objectives.Add(name, obj);
        return obj;
      }
    }
  }
}
