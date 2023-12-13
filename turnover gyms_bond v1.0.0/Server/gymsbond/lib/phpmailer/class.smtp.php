<?php
/**
 * PHPMailer RFC821 SMTP email transport class.
 * PHP Version 5
 * @package PHPMailer
 * @link https://github.com/PHPMailer/PHPMailer/ The PHPMailer GitHub project
 * @author Marcus Bointon (Synchro/coolbru) <phpmailer@synchromedia.co.uk>
 * @author Jim Jagielski (jimjag) <jimjag@gmail.com>
 * @author Andy Prevost (codeworxtech) <codeworxtech@users.sourceforge.net>
 * @author Brent R. Matzelle (original founder)
 * @copyright 2014 Marcus Bointon
 * @copyright 2010 - 2012 Jim Jagielski
 * @copyright 2004 - 2009 Andy Prevost
 * @license http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 * @note This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/**
 * PHPMailer RFC821 SMTP email transport class.
 * Implements RFC 821 SMTP commands and provides some utility methods for sending mail to an SMTP server.
 * @package PHPMailer
 * @author Chris Ryan
 * @author Marcus Bointon <phpmailer@synchromedia.co.uk>
 */
class SMTP
{
    /**
     * The PHPMailer SMTP version number.
     * @var string
     */
    const VERSION = '5.2.15';

    /**
     * SMTP line break constant.
     * @var string
     */
    const CRLF = "\r\n";

    /**
     * The SMTP port to use if one is not specified.
     * @var integer
     */
    const DEFAULT_SMTP_PORT = 25;

    /**
     * The maximum line length allowed by RFC 2822 section 2.1.1
     * @var integer
     */
    const MAX_LINE_LENGTH = 998;

    /**
     * Debug level for no output
     */
    const DEBUG_OFF = 0;

    /**
     * Debug level to show client -> server messages
     */
    const DEBUG_CLIENT = 1;

    /**
     * Debug level to show client -> server and server -> client messages
     */
    const DEBUG_SERVER = 2;

    /**
     * Debug level to show connection status, client -> server and server -> client messages
     */
    const DEBUG_CONNECTION = 3;

    /**
     * Debug level to show all messages
     */
    const DEBUG_LOWLEVEL = 4;

    /**
     * The PHPMailer SMTP Version number.
     * @var string
     * @deprecated Use the `VERSION` constant instead
     * @see SMTP::VERSION
     */
    public $Version = '5.2.15';

    /**
     * SMTP server port number.
     * @var integer
     * @deprecated This is only ever used as a default value, so use the `DEFAULT_SMTP_PORT` constant instead
     * @see SMTP::DEFAULT_SMTP_PORT
     */
    public $SMTP_PORT = 25;

    /**
     * SMTP reply line ending.
     * @var string
     * @deprecated Use the `CRLF` constant instead
     * @see SMTP::CRLF
     */
    public $CRLF = "\r\n";

    /**
     * Debug output level.
     * Options:
     * * self::DEBUG_OFF (`0`) No debug output, default
     * * self::DEBUG_CLIENT (`1`) Client commands
     * * self::DEBUG_SERVER (`2`) Client commands and server responses
     * * self::DEBUG_CONNECTION (`3`) As DEBUG_SERVER plus connection status
     * * self::DEBUG_LOWLEVEL (`4`) Low-level data output, all messages
     * @var integer
     */
    public $do_debug = self::DEBUG_OFF;

    /**
     * How to handle debug output.
     * Options:
     * * `echo` Output plain-text as-is, appropriate for CLI
     * * `html` Output escaped, line breaks converted to `<br>`, appropriate for browser output
     * * `error_log` Output to error log as configured in php.ini
     *
     * Alternatively, you can provide a callable expecting two params: a message string and the debug level:
     * <code>
     * $smtp->Debugoutput = function($str, $level) {echo "debug level $level; message: $str";};
     * </code>
     * @var string|callable
     */
    public $Debugoutput = 'echo';

    /**
     * Whether to use VERP.
     * @link http://en.wikipedia.org/wiki/Variable_envelope_return_path
     * @link http://www.postfix.org/VERP_README.html Info on VERP
     * @var boolean
     */
    public $do_verp = false;

    /**
     * The timeout value for connection, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2
     * This needs to be quite high to function correctly with hosts using greetdelay as an anti-spam measure.
     * @link http://tools.ietf.org/html/rfc2821#section-4.5.3.2
     * @var integer
     */
    public $Timeout = 300;

    /**
     * How long to wait for commands to complete, in seconds.
     * Default of 5 minutes (300sec) is from RFC2821 section 4.5.3.2
     * @var integer
     */
    public $Timelimit = 300;

    /**
     * The socket for the server connection.
     * @var resource
     */
    protected $smtp_conn;

    /**
     * Error information, if any, for the last SMTP command.
     * @var array
     */
    protected $error = array(
        'error' => '',
        'detail' => '',
        'smtp_code' => '',
        'smtp_code_ex' => ''
    );

    /**
     * The reply the server sent to us for HELO.
     * If null, no HELO string has yet been received.
     * @var string|null
     */
    protected $helo_rply = null;

    /**
     * The set of SMTP extensions sent in reply to EHLO command.
     * Indexes of the array are extension names.
     * Value at index 'HELO' or 'EHLO' (according to command that was sent)
     * represents the server name. In case of HELO it is the only element of the array.
     * Other values can be boolean TRUE or an array containing extension options.
     * If null, no HELO/EHLO string has yet been received.
     * @var array|null
     */
    protected $server_caps = null;

    /**
     * The most recent reply received from the server.
     * @var string
     */
    protected $last_reply = '';

    /**
     * Output debugging info via a user-selected method.
     * @see SMTP::$Debugoutput
     * @see SMTP::$do_debug
     * @param string $str Debug string to output
     * @param integer $level The debug level of this message; see DEBUG_* constants
     * @return void
     */
    protected function edebug($str, $level = 0)
    {
        if ($level > $this->do_debug) {
            return;
        }
        //Avoid clash with built-in function names
        if (!in_array($this->Debugoutput, array('error_log', 'html', 'echo')) and is_callable($this->Debugoutput)) {
            call_user_func($this->Debugoutput, $str, $this->do_debug);
            return;
        }
        switch ($this->Debugoutput) {
            case 'error_log':
                //Don't output, just log
                error_log($str);
                break;
            case 'html':
                //Cleans up output a bit for a better looking, HTML-safe output
                echo htmlentities(
                    preg_replace('/[\r\n]+/', '', $str),
                    ENT_QUOTES,
                    'UTF-8'
                )
                . "<br>\n";
                break;
            case 'echo':
            default:
                //Normalize line breaks
                $str = preg_replace('/(\r\n|\r|\n)/ms', "\n", $str);
                echo gmdate('Y-m-d H:i:s') . "\t" . str_replace(
                    "\n",
                    "\n                   \t                  ",
                    trim($str)
                )."\n";
        }
    }

    /**
     * Connect to an SMTP server.
     * @param string $host SMTP server IP or host name
     * @param integer $port The port number to connect to
     * @param integer $timeout How long to wait for the connection to open
     * @param array $options An array of options for stream_context_create()
     * @access public
     * @return boolean
     */
    public function connect($host, $port = null, $timeout = 30, $options = array())
    {
        static $streamok;
        //This is enabled by default since 5.0.0 but some providers disable it
        //Check this once and cache the result
        if (is_null($streamok)) {
            $streamok = function_exists('stream_socket_client');
        }
        // Clear errors to avoid confusion
        $this->setError('');
        // Make sure we are __not__ connected
        if ($this->connected()) {
            // Already connected, generate error
            $this->setError('Already connected to a server');
            return false;
        }
        if (empty($port)) {
            $port = self::DEFAULT_SMTP_PORT;
        }
        // Connect to the SMTP server
        $this->edebug(
            "Connection: opening to $host:$port, timeout=$timeout, options=".var_export($options, true),
            self::DEBUG_CONNECTION
        );
        $errno = 0;
        $errstr = '';
        if ($streamok) {
            $socket_context = stream_context_create($options);
            //Suppress errors; connection failures are handled at a higher level
            $this->smtp_conn = @stream_socket_client(
                $host . ":" . $port,
                $errno,
                $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $socket_context
            );
        } else {
            //Fall back to fsockopen which should work in more places, but is missing some features
            $this->edebug(
                "Connection: stream_socket_client not available, falling back to fsockopen",
                self::DEBUG_CONNECTION
            );
            $this->smtp_conn = fsockopen(
                $host,
                $port,
                $errno,
                $errstr,
                $timeout
            );
        }
        // Verify we connected properly
        if (!is_resource($this->smtp_conn)) {
            $this->setError(
                'Failed to connect to server',
                $errno,
                $errstr
            );
            $this->edebug(
                'SMTP ERROR: ' . $this->error['error']
                . ": $errstr ($errno)",
                self::DEBUG_CLIENT
            );
            return false;
        }
        $this->edebug('Connection: opened', self::DEBUG_CONNECTION);
        // SMTP server can take longer to respond, give longer timeout for first read
        // Windows does not have support for this timeout function
        if (substr(PHP_OS, 0, 3) != 'WIN') {
            $max = ini_get('max_execution_time');
            // Don't bother if unlimited
            if ($max != 0 && $timeout > $max) {
                @set_time_limit($timeout);
            }
            stream_set_timeout($this->smtp_conn, $timeout, 0);
        }
        // Get any announcement
        $announce = $this->get_lines();
        $this->edebug('SERVER -> CLIENT: ' . $announce, self::DEBUG_SERVER);
        return true;
    }

    /**
     * Initiate a TLS (encrypted) session.
     * @access public
     * @return boolean
     */
    public function startTLS()
    {
        if (!$this->sendCommand('STARTTLS', 'STARTTLS', 220)) {
            return false;
        }

        //Allow the best TLS version(s) we can
        $crypto_method = STREAM_CRYPTO_METHOD_TLS_CLIENT;

        //PHP 5.6.7 dropped inclusion of TLS 1.1 and 1.2 in STREAM_CRYPTO_METHOD_TLS_CLIENT
        //so add them back in manually if we can
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
            $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            $crypto_method |= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
        }

        // Begin encrypted connection
        if (!stream_socket_enable_crypto(
            $this->smtp_conn,
            true,
            $crypto_method
        )) {
            return false;
        }
        return true;
    }

    /**
     * Perform SMTP authentication.
     * Must be run after hello().
     * @see hello()
     * @param string $username The user name
     * @param string $password The password
     * @param string $authtype The auth type (PLAIN, LOGIN, NTLM, CRAM-MD5, XOAUTH2)
     * @param string $realm The auth realm for NTLM
     * @param string $workstation The auth workstation for NTLM
     * @param null|OAuth $OAuth An optional OAuth instance (@see PHPMailerOAuth)
     * @return bool True if successfully authenticated.* @access public
     */
    public function authenticate(
        $username,
        $password,
        $authtype = null,
        $realm = '',
        $workstation = '',
        $OAuth = null
    ) {
        if (!$this->server_caps) {
      <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand\Assistant;

use Twilio\Exceptions\TwilioException;
use Twilio\InstanceResource;
use Twilio\Values;
use Twilio\Version;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 *
 * @property string $accountSid
 * @property string $assistantSid
 * @property string $sid
 * @property array $data
 * @property string $url
 */
class DialogueInstance extends InstanceResource {
    /**
     * Initialize the DialogueInstance
     *
     * @param Version $version Version that contains the resource
     * @param mixed[] $payload The response payload
     * @param string $assistantSid The unique ID of the parent Assistant.
     * @param string $sid The sid
     */
    public function __construct(Version $version, array $payload, string $assistantSid, string $sid = null) {
        parent::__construct($version);

        // Marshaled Properties
        $this->properties = [
            'accountSid' => Values::array_get($payload, 'account_sid'),
            'assistantSid' => Values::array_get($payload, 'assistant_sid'),
            'sid' => Values::array_get($payload, 'sid'),
            'data' => Values::array_get($payload, 'data'),
            'url' => Values::array_get($payload, 'url'),
        ];

        $this->solution = ['assistantSid' => $assistantSid, 'sid' => $sid ?: $this->properties['sid'], ];
    }

    /**
     * Generate an instance context for the instance, the context is capable of
     * performing various actions.  All instance actions are proxied to the context
     *
     * @return DialogueContext Context for this DialogueInstance
     */
    protected function proxy(): DialogueContext {
        if (!$this->context) {
            $this->context = new DialogueContext(
                $this->version,
                $this->solution['assistantSid'],
                $this->solution['sid']
            );
        }

        return $this->context;
    }

    /**
     * Fetch the DialogueInstance
     *
     * @return DialogueInstance Fetched DialogueInstance
     * @throws TwilioException When an HTTP error occurs.
     */
    public function fetch(): DialogueInstance {
        return $this->proxy()->fetch();
    }

    /**
     * Magic getter to access properties
     *
     * @param string $name Property to access
     * @return mixed The requested property
     * @throws TwilioException For unknown properties
     */
    public function __get(string $name) {
        if (\array_key_exists($name, $this->properties)) {
            return $this->properties[$name];
        }

        if (\property_exists($this, '_' . $name)) {
            $method = 'get' . \ucfirst($name);
            return $this->$method();
        }

        throw new TwilioException('Unknown property: ' . $name);
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        $context = [];
        foreach ($this->solution as $key => $value) {
            $context[] = "$key=$value";
        }
        return '[Twilio.Preview.Understand.DialogueInstance ' . \implode(' ', $context) . ']';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand\Assistant;

use Twilio\ListResource;
use Twilio\Version;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 */
class DialogueList extends ListResource {
    /**
     * Construct the DialogueList
     *
     * @param Version $version Version that contains the resource
     * @param string $assistantSid The unique ID of the parent Assistant.
     */
    public function __construct(Version $version, string $assistantSid) {
        parent::__construct($version);

        // Path Solution
        $this->solution = ['assistantSid' => $assistantSid, ];
    }

    /**
     * Constructs a DialogueContext
     *
     * @param string $sid The sid
     */
    public function getContext(string $sid): DialogueContext {
        return new DialogueContext($this->version, $this->solution['assistantSid'], $sid);
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        return '[Twilio.Preview.Understand.DialogueList]';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand\Assistant;

use Twilio\Http\Response;
use Twilio\Page;
use Twilio\Version;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 */
class DialoguePage extends Page {
    /**
     * @param Version $version Version that contains the resource
     * @param Response $response Response from the API
     * @param array $solution The context solution
     */
    public function __construct(Version $version, Response $response, array $solution) {
        parent::__construct($version, $response);

        // Path Solution
        $this->solution = $solution;
    }

    /**
     * @param array $payload Payload response from the API
     * @return DialogueInstance \Twilio\Rest\Preview\Understand\Assistant\DialogueInstance
     */
    public function buildInstance(array $payload): DialogueInstance {
        return new DialogueInstance($this->version, $payload, $this->solution['assistantSid']);
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        return '[Twilio.Preview.Understand.DialoguePage]';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand\Assistant;

use Twilio\Options;
use Twilio\Values;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 */
abstract class StyleSheetOptions {
    /**
     * @param array $styleSheet The JSON Style sheet string
     * @return UpdateStyleSheetOptions Options builder
     */
    public static function update(array $styleSheet = Values::ARRAY_NONE): UpdateStyleSheetOptions {
        return new UpdateStyleSheetOptions($styleSheet);
    }
}

class UpdateStyleSheetOptions extends Options {
    /**
     * @param array $styleSheet The JSON Style sheet string
     */
    public function __construct(array $styleSheet = Values::ARRAY_NONE) {
        $this->options['styleSheet'] = $styleSheet;
    }

    /**
     * The JSON Style sheet string
     *
     * @param array $styleSheet The JSON Style sheet string
     * @return $this Fluent Builder
     */
    public function setStyleSheet(array $styleSheet): self {
        $this->options['styleSheet'] = $styleSheet;
        return $this;
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        $options = \http_build_query(Values::of($this->options), '', ' ');
        return '[Twilio.Preview.Understand.UpdateStyleSheetOptions ' . $options . ']';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand\Assistant;

use Twilio\Http\Response;
use Twilio\Page;
use Twilio\Version;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 */
class QueryPage extends Page {
    /**
     * @param Version $version Version that contains the resource
     * @param Response $response Response from the API
     * @param array $solution The context solution
     */
    public function __construct(Version $version, Response $response, array $solution) {
        parent::__construct($version, $response);

        // Path Solution
        $this->solution = $solution;
    }

    /**
     * @param array $payload Payload response from the API
     * @return QueryInstance \Twilio\Rest\Preview\Understand\Assistant\QueryInstance
     */
    public function buildInstance(array $payload): QueryInstance {
        return new QueryInstance($this->version, $payload, $this->solution['assistantSid']);
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        return '[Twilio.Preview.Understand.QueryPage]';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        <?php

/**
 * This code was generated by
 * \ / _    _  _|   _  _
 * | (_)\/(_)(_|\/| |(/_  v1.0.0
 * /       /
 */

namespace Twilio\Rest\Preview\Understand;

use Twilio\Http\Response;
use Twilio\Page;
use Twilio\Version;

/**
 * PLEASE NOTE that this class contains preview products that are subject to change. Use them with caution. If you currently do not have developer preview access, please contact help@twilio.com.
 */
class AssistantPage extends Page {
    /**
     * @param Version $version Version that contains the resource
     * @param Response $response Response from the API
     * @param array $solution The context solution
     */
    public function __construct(Version $version, Response $response, array $solution) {
        parent::__construct($version, $response);

        // Path Solution
        $this->solution = $solution;
    }

    /**
     * @param array $payload Payload response from the API
     * @return AssistantInstance \Twilio\Rest\Preview\Understand\AssistantInstance
     */
    public function buildInstance(array $payload): AssistantInstance {
        return new AssistantInstance($this->version, $payload);
    }

    /**
     * Provide a friendly representation
     *
     * @return string Machine friendly representation
     */
    public function __toString(): string {
        return '[Twilio.Preview.Understand.AssistantPage]';
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ÕÎKö⁄£ÁJÎE¬≈¸[¨ì;å¥±Î*ÊñÓ…tÍ§ÆåÁïYñ@Z¿ËÕxƒ#Ë=>TXÁæN'øW1ˇ˛ù7¯ÓÎ8fpLë`â>ˆÑ∞• ßîäË
è Ÿπ?S¥|f+ªÒgà[∆t0_¢Cæ√Tõ†ô_Ù3>-I¿`eÙU¨0ÂÚgï¬¥±+˜láræ¡;Ä	#c`{{±hq,&Ù"XÃg3f∑osÁùw∏ÛÓªÃﬁzÁè‹≠ª®oæ¶çÄrØ∂Ó˜≈ù˛n{lΩfµ:£€,	KGW–⁄≥¶.Ò%Ìƒ–!é^ør·~}Î“eÃÄa^®≤ì£_⁄ 0{Í&¿°q,{ﬁ
™ä…M)WdçF˘ù“PõÃœÌ¸ô¯˛]ú¥”r¯S◊g¶H·o,£Òã>í‹º‹EÚ€xûØ€ı	—Œ˙2=èK1…Ñø∑gªˆzÔzû\\c.g´›Ï£oéœO˝u´``ìf¿+ÛÄÙœ°ZÏÓ 6]Tßx™f¿Ì€∑ˇ«/|·«˛œgg'ú=>·ÙÙÑı˘8ﬂô˜Sv¿°˙≠™Ó¯ÃyË˚ûÆÀ∑æÔﬂªiºbÕÄ˝Ü¿≈ÁÖÎû}Õ"¨OΩNx√ˇ£M:Í6)úÖóAbgèÇ6$ñÄ&”¡ù‰JÂÒΩê⁄ûN≠∫Q¥Ÿ&¸⁄Rh_&a ;˝î.‰«πT
ç1ÀH»»÷iÅ8éßûuD])
Ëö±l
Z(ÜlLñı∆}TR∏iº
GüÏmŸt=´Æ£m{bê‚™ûëNÖ#Ö˙¸˙{^TÂ$>eÏπÙHª‹C—G˜qªÚ?ÉñÙhÏ›(§Z$ÅúÉ∫¬´"µß™*™Y.Çª∫ zıGs‘5hU°Œ—$¡B¶–ILƒÆÉMGª:'úü“≠VhÃ±¢ÍÌqC◊u_˝Kx˚W·S—Ø}ˇ…¸ÊG>˙›{˜>¯ÌèN~¬áè>‡£«rrv¬…˙1´~EH=[°Nê hjáõnÆÅj.T3¡U>ÎÇR1S)ÍRpœ6 $∞W‘ﬂ’ø∞EíÅïv6
cA¿%í:5Ç‚*6öpNX‚p—£-§UßBw*§;¬zc¯µ∞<Ú,ŒÎç∫UΩR∑ÇÆ¡ØåÿG$eÄ≥‘K∞Ñâ«©:fÍH8Çub‘ Vß®€ÛœF¶V÷Ø√Ûhüq3"<o¬ÏKœ¨¨˝ﬁ2B\3(òﬁKFÚ'
èB‚!ë8M∆©Aï‰)ñ"@AT¶!˛§^¨j`Ófä7eÊå„≠BÂÑÄÉ‰JÕÿz0e2|>éTêíek“òÌñÎák°B/ikà[P€&˘eÕÂ`—›≥EÊL kRπáëHrB_	m-¨jaS≠OlºÅD∫⁄hkÂ|.ú¡r°léÖÂ¬°wfÑ€‹ÚÙ3G®ïx‰â.˚G,còÑîı≤-oJ4Å¶ÃRÿ1*‚¿\\ºòìÀ^s`˙πu⁄∞Ω".€Î6¥≥mèÓΩﬂdOÖ-õ,fNî…âûûmÊ"Z¢vD∑Ü¶˚√X?˘£EuÁèﬁÆ^-c·aM«åà«äfw4h…F“Ω¡™ÔÈíå¶µA¨ ’§4Ó?ƒ"*:zíF-ëÜ
/Ü◊≤&X^;t–¨+d©|ïm)ÎøãR)‘öàÖΩñ‘°Qä∑¡e)≈√àT∂Hfëﬂ”k…ﬂWØKf(ôÂ4·DQ≤G4√
¿*⁄8Íù;!a)d…â˘>d◊‘gE ÷§BJÙ*t~F ∫∫¡sÍ„ªÿõÔPΩ˚™wÒè¸ùØ¸7rÎ◊ﬁ›„¶ø˝?Ù∑˘g}3˚a–„#qé$Ír·ﬂZú®@B¬≈ÏÈ≠\◊¬<Rg$·1úYÒK…L ïÑõjŸæ‰FÄLXe©Ãk^˘{%äGÒdvàO‡3qjHÚ/∑ü— ˚2 ¢≥º&cô!Ω“'#™`©'Hˆ	0U\b•DQíA≤_@*Ã—¥À~u"”¡	î„êœ⁄˚¢Då÷†3hMËÃ—ØÄ πÒKò–L¡A≈· ≥ëÿ˙/‰|¢Ï@KNÆ§≠Œ·0Ò-◊P…EÀÚ.!
≠≠&"Büå@>ª†ÿ∞çiWBI≥ÔÇZˆzÃÜÑàÀksíû]˘%±õ\¯Ê¯‘Wá‹ v•≈¢e¿A*π€ ‰P\ﬂké^h‰^!è¸¥M›_¯Â_=7Kø/Ñ/>xÒ?¯¯Œq>õMª“Ë˚ÕÄ˝Û€>&éuõi3†ﬂ4n&œ§X„ˆ¿NÏ ˝e˙¯Ògï“"Bë•≤ı®»∂eÇ¶bEà„9Ö.Î˚†cQrËÿ3-∆àJFòY‹¢I«ØÒ‰ï4zó^Ùò~ûCzb7«+∞ë,≈Á)›ÈPWvß®ys<◊u~⁄«lë„€¬ø™éÕÅ∫ÆÛœÖ	@âC3¿\FÔIÌ≥Œ,3|SÉwÿlÜwuù•Å‘î‘Á{Oàúûùë÷VÁÁÙggÑÕ&±I¢NëÆÎË˚˛[!˛ìo¸ÙÏGoüûû˛÷√á˚ﬁΩ{<:}ƒ£GèxÚ‰	ÀÂí∂mâ≥©≤sŸrÔ∫„<•D]ÃÉß1i˙ÿ©LêBó¶ÙTs b„Ûî)%{ÜDÏÈ[Ò^úCºá∫ÜôîÕ/ÃÁ∆<Êçsπ‡¨«'#Xããn4ÓÑ¡H3Å§i¿pÓ%a[dÔ≈Á≈“ÊÕÒÍ‰ÉÈÍ8ﬁŸÆÌ1ejLŸTq;¶«ü•^X”ı`ä"º<≤õXœa∆Ëîy94Å”^urç›7Œï¥’ùﬁı¯âÂı2É#ÉV.jö3¢ûﬁ;™
ö¶¬!Œ<°¸Õ&q0∆Ç*'"N/—Ë‰‚ı‡µ6_óÅd¶H¨ÏØròÅk°f;Ø3Õï«Œ±∂#ÖG¥àò$ØÖõÕÜµ[≥¨ñú’goWÍ~'T≤z˚≠◊á!0Ω/ô@F•õ^º&„—+˜9SdÏ°ç˚eõÈq<OP”™Çöf]˝bîmœ0«^(ª0ˆd∑x7bÏ†‘ü¶P+ˆ@∏mêÔAº˜‘Z#≥ÃÁ4M√|>g±X0õœøœÁ†0=™££Ô˘ˆ¯√Ì€ﬂˆÀ€t›∫ˆåu˚Ñê:RøÇƒûÓ¥]ä¨>»ûˇÚ˙Cû˚9®å.o<√ÿŒ◊dÚ˛%ﬂLñõ£ö2;¿%–ã\€°õ\ÚŸ‰πØK≤îÕÉß$€Ûîô¨cóΩ◊AÉÚ´ﬂ|d	™=dñ£Ïy°ŸŒµ‹πæOsˆ=nºınéœΩs∏⁄ÛödﬂgP.]'˜u˙3;»^JˇˆKøÚkuÎÛˇÂ¯¯¯,ã¨P◊;!vﬂ‡Ä¸ê«A ÅmÀÍÎ{båoﬂ4..ãﬁ˚q#!‚È˚û¶i∆ã´ì§s†TÓ,nóñÏôÌ•õàÁL4ØÒ˚2∑KÖ∂Ωœ4£&PÀhqD;MÖÆÙe k à◊8,%ú´ê˘<ˇæ¯´≤V›&Ê©lO——îÕ1¨–uêìà®«•Ñ§D
mÈ%!%T"E_SµÇÜA©™ıé∂ÔÈBOt|ï°∫7«gz¸ÂÈÚΩeæ±IâU¨∫ûuﬂ≥ﬁÇ%∫î;†:1‹7\}Ÿµg[åûÛ˘»ïÁ{›˘€5Å¬ÖM .%NÀ∆<çZù)Z6ãﬁÁÁ∏ºINﬁaﬁS’5æ™pUïç¸ö:7ö¸Û`D©u5>ﬂ9ó}º«JÛ &êäå∞J	/EÒ£ÔYüùcÁÁÙÀ5´˜Yùûa}ãÑD‹Ã9zÎû<yB¸“;üäYËœñˇÎWúﬁ˚ŒΩá|Áﬁ…œ8Yﬂ„˛ìèxº|¿√≥˚t]á˘DL}Ï±*·=¯π√+~&43e6s‘3E]Dµﬁa`8Á.EÏoÊQ«∏=ZØîÜ¬∞L‹Ehú5#ìâH`]™Éû¶ÆÒÔ∞Ja.Ñ–`m‚Ò-Â|⁄ö¨VëfôpK£97l≥Œà]$Æ!v©ê·b2x »`*5áFFmSßYo{l`H"	ÙÂ:8‹⁄[ˆhŸ6R*/)nNäåO[L}ëy•˘∂»ßøûÁ|w«bqi®÷kˆÍ´ÜUÏ8±¿#åÖì ß¡8:õ!>={Ÿ+Bô∆ﬂ
‘¨»AıÃ‚ä[)Àí’Nô•∏ì9À I&‚2Ò8yMã˚€¯Ø|‹v-Ú¿›|pYOR¡=›|Wå∫˝‘<sœ®πu=I êŒàÈI$"Q πD◊(°÷ç≤ûÌ¬√¨b≥úπ›¢"Õ+÷3ÂlŸÃî˛HÈé<“8B%§*bNIU"¶ûPﬁﬂ_Ó≥ 1É ]⁄2@¨0_ìê◊/…Ò&ïÀ0ãªEd∆¶Hé¡#sv>{≤Bó‰◊[âÎr≠tk<Í&œYÖeñgÛ©äFtBÏsé„±@ølÈ§%Ëä®k˙ÍmÓwﬂ˘Àì?˘„_}„ìaLõ”˚íCq:àÊ≥'«e<ÃcÁI‰Ç`ü»:›!“ÖîuªMËRFˇvõ¥¯M F*ÜsF-éJü®†"®∏¨ï≠
VƒﬁïöyÇ¡9Dïd1kÍMá‚U:0Ìl