using Renci.SshNet.Common;
using Renci.SshNet.Messages;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Renci.SshNet
{
    /// <summary>
    /// Provides functionality to perform smart card authentication.
    /// Copied and edited code from <see cref="PrivateKeyAuthenticationMethod"/> 
    /// </summary>
    public class SmartcardAuthenticationMethod : AuthenticationMethod, IDisposable
    {
        private AuthenticationResult _authenticationResult = AuthenticationResult.Failure;

        private EventWaitHandle _authenticationCompleted = new ManualResetEvent(false);

        /// <summary>
        /// Initializes a new instance of the <see cref="SmartcardAuthenticationMethod"/> class.
        /// </summary>
        /// <param name="username">The username.</param>
        public SmartcardAuthenticationMethod(string username) : base(username)
        {
        }

        /// <summary>
        /// Gets authentication method name
        /// </summary>
        public override string Name
        {
            get { return "publickey"; }
        }

        /// <summary>
        /// Authenticates the specified session.
        /// </summary>
        /// <param name="session">The session to authenticate.</param>
        /// <returns>
        /// Result of authentication  process.
        /// </returns>
        public override AuthenticationResult Authenticate(Session session)
        {
            session.UserAuthenticationSuccessReceived += Session_UserAuthenticationSuccessReceived;
            session.UserAuthenticationFailureReceived += Session_UserAuthenticationFailureReceived;
            session.UserAuthenticationPublicKeyReceived += Session_UserAuthenticationPublicKeyReceived;

            session.RegisterMessage("SSH_MSG_USERAUTH_PK_OK");

            try
            {
                X509Certificate2 clientCert = GetClientCertificate();

                CspParameters csp = new CspParameters(1, "Microsoft Base Smart Card Crypto Provider");
                csp.Flags = CspProviderFlags.UseDefaultKeyContainer;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
                var keyParams = rsa.ExportParameters(false);
                var HostKey = RsaKeyHostAlgorithm.Create(rsa);

                _authenticationCompleted.Reset();

                var message = new RequestMessagePublicKey(ServiceName.Connection,
                                                          Username,
                                                          HostKey.Name,
                                                          HostKey.Data
                                                         );

                var signatureData = new SignatureData(message, session.SessionId).GetBytes();

                message.Signature = HostKey.Sign(signatureData);

                //System.Diagnostics.Debug.Assert(rsa.VerifyData(signatureData, SHA1.Create(), message.Signature));

                // Send public key authentication request with signature
                session.SendMessage(message);

                session.WaitOnHandle(_authenticationCompleted);

                return _authenticationResult;
            }
            finally
            {
                session.UserAuthenticationSuccessReceived -= Session_UserAuthenticationSuccessReceived;
                session.UserAuthenticationFailureReceived -= Session_UserAuthenticationFailureReceived;
                session.UserAuthenticationPublicKeyReceived -= Session_UserAuthenticationPublicKeyReceived;
                session.UnRegisterMessage("SSH_MSG_USERAUTH_PK_OK");
            }
        }

        private void Session_UserAuthenticationSuccessReceived(object sender, MessageEventArgs<SuccessMessage> e)
        {
            _authenticationResult = AuthenticationResult.Success;

            _authenticationCompleted.Set();
        }

        private void Session_UserAuthenticationFailureReceived(object sender, MessageEventArgs<FailureMessage> e)
        {
            if (e.Message.PartialSuccess)
                _authenticationResult = AuthenticationResult.PartialSuccess;
            else
                _authenticationResult = AuthenticationResult.Failure;

            //  Copy allowed authentication methods
            AllowedAuthentications = e.Message.AllowedAuthentications;

            _authenticationCompleted.Set();
        }

        private void Session_UserAuthenticationPublicKeyReceived(object sender, MessageEventArgs<PublicKeyMessage> e)
        {
            _authenticationCompleted.Set();
        }

        private X509Certificate2 GetClientCertificate()
        {
            IntPtr ptr = IntPtr.Zero;
            X509Certificate2 certificate = null;
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                if (store.Certificates != null && store.Certificates.Count > 0)
                {
                    if (store.Certificates.Count == 1)
                    {
                        certificate = store.Certificates[0];
                    }
                    else
                    {
                        var certificates = new X509Certificate2Collection();

                        foreach (var cert in store.Certificates)
                        {
                            if (cert.HasPrivateKey && cert.Issuer.IndexOf("test", StringComparison.OrdinalIgnoreCase) < 0)
                            {
                                //X509Chain ch = new X509Chain();
                                //ch.Build(cert);

                                foreach (X509Extension ext in cert.Extensions)
                                {
                                    if (ext.GetType() == typeof(X509EnhancedKeyUsageExtension))
                                    {
                                        foreach (var type in ((X509EnhancedKeyUsageExtension)ext).EnhancedKeyUsages)
                                        {
                                            if ("1.3.6.1.4.1.311.20.2.2".Equals(type.Value))    // Smart Card Logon
                                            {
                                                certificates.Add(cert);
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }

                        if (certificates.Count == 1)
                        {
                            certificate = certificates[0];
                        }
                        else if (certificates.Count > 1)
                        {
                            certificates = X509Certificate2UI.SelectFromCollection(certificates, "Digital Certificates", "Select a certificate from the following list:", X509SelectionFlag.SingleSelection, ptr);

                            if (certificates != null && certificates.Count > 0)
                                certificate = certificates[0];
                        }

                        if (certificate == null)
                            throw new ArgumentException("Could not find proper certificate for authentication!");
                    }
                }
            }
            finally
            {
                store.Close();
            }

            return certificate;
        }

        #region IDisposable Members

        private bool _isDisposed;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
                return;

            if (disposing)
            {
                var authenticationCompleted = _authenticationCompleted;

                if (authenticationCompleted != null)
                {
                    _authenticationCompleted = null;
                    authenticationCompleted.Dispose();
                }

                _isDisposed = true;
            }
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="PasswordConnectionInfo"/> is reclaimed by garbage collection.
        /// </summary>
        ~SmartcardAuthenticationMethod()
        {
            Dispose(false);
        }

        #endregion

        private class RsaKeyHostAlgorithm : KeyHostAlgorithm
        {
            private RsaKeyHostAlgorithm(RSACryptoServiceProvider rsa, SmartCardKey key)
                : base("ssh-rsa", key) { }

            /// <summary>
            /// Creates an RsaKeyHostAlgorithm using a RSACryptoServiceProvider
            /// </summary>
            /// <param name="rsa"></param>
            /// <returns></returns>
            public static RsaKeyHostAlgorithm Create(RSACryptoServiceProvider rsa)
            {
                if (rsa == null)
                    throw new ArgumentNullException("rsa");

                var keyParams = rsa.ExportParameters(false);
                var _key = new SmartCardKey(rsa, GetBig(keyParams.Modulus), GetBig(keyParams.Exponent), GetBig(keyParams.D), GetBig(keyParams.P), GetBig(keyParams.Q), GetBig(keyParams.InverseQ));

                return new RsaKeyHostAlgorithm(rsa, _key);
            }

            private static BigInteger GetBig(byte[] value)
            {
                if (value != null)  // if private key is missing, the value is null
                {
                    byte[] inArr = (byte[])value.Clone();
                    Array.Reverse(inArr);  // Reverse the byte order
                    byte[] final = new byte[inArr.Length + 1];  // Add an empty byte at the end, to simulate unsigned BigInteger (no negatives!)
                    Array.Copy(inArr, final, inArr.Length);

                    return new BigInteger(final);
                }

                return new BigInteger();
            }
        }

        private class SignatureData : SshData
        {
            private readonly RequestMessagePublicKey _message;

            private readonly byte[] _sessionId;
            private readonly byte[] _serviceName;
            private readonly byte[] _authenticationMethod;

            protected override int BufferCapacity
            {
                get
                {
                    var capacity = base.BufferCapacity;
                    capacity += 4; // SessionId length
                    capacity += _sessionId.Length; // SessionId
                    capacity += 1; // Authentication Message Code
                    capacity += 4; // UserName length
                    capacity += _message.Username.Length; // UserName
                    capacity += 4; // ServiceName length
                    capacity += _serviceName.Length; // ServiceName
                    capacity += 4; // AuthenticationMethod length
                    capacity += _authenticationMethod.Length; // AuthenticationMethod
                    capacity += 1; // TRUE
                    capacity += 4; // PublicKeyAlgorithmName length
                    capacity += _message.PublicKeyAlgorithmName.Length; // PublicKeyAlgorithmName
                    capacity += 4; // PublicKeyData length
                    capacity += _message.PublicKeyData.Length; // PublicKeyData
                    return capacity;
                }
            }

            public SignatureData(RequestMessagePublicKey message, byte[] sessionId)
            {
                _message = message;
                _sessionId = sessionId;
                _serviceName = ServiceName.Connection.ToArray();
                _authenticationMethod = Ascii.GetBytes("publickey");
            }

            protected override void LoadData()
            {
                throw new NotImplementedException();
            }

            protected override void SaveData()
            {
                WriteBinaryString(_sessionId);
                Write((byte)RequestMessage.AuthenticationMessageCode);
                WriteBinaryString(_message.Username);
                WriteBinaryString(_serviceName);
                WriteBinaryString(_authenticationMethod);
                Write((byte)1); // TRUE
                WriteBinaryString(_message.PublicKeyAlgorithmName);
                WriteBinaryString(_message.PublicKeyData);
            }
        }

        private class SmartCardKey : RsaKey
        {
            private readonly SmartCardSignature signature;

            public SmartCardKey(RSACryptoServiceProvider rsa, BigInteger modulus, BigInteger exponent, BigInteger d, BigInteger p, BigInteger q, BigInteger inverseQ)
                : base(modulus, exponent, d, p, q, inverseQ)
            {
                signature = new SmartCardSignature(rsa);
            }

            protected override DigitalSignature DigitalSignature
            {
                get
                {
                    return signature;
                }
            }
        }

        private class SmartCardSignature : DigitalSignature
        {
            private RSACryptoServiceProvider rsa;
            private HashAlgorithm hash;

            public SmartCardSignature(RSACryptoServiceProvider rsa)
            {
                this.rsa = rsa;
                this.hash = SHA1.Create();
            }

            public override byte[] Sign(byte[] input)
            {
                return rsa.SignData(input, hash);
            }

            public override bool Verify(byte[] input, byte[] signature)
            {
                return rsa.VerifyData(input, hash, signature);
            }
        }
    }
}
