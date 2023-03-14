/* ========================================================================
 * Copyright (c) 2005-2020 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;

namespace Quickstarts
{
    /// <summary>
    /// OPC UA Client with examples of basic functionality.
    /// </summary>
    public class UAClient : IDisposable
    {
        #region Constructors
        /// <summary>
        /// Initializes a new instance of the UAClient class.
        /// </summary>
        public UAClient(ApplicationConfiguration configuration, TextWriter writer, Action<IList, IList> validateResponse)
        {
            m_sessions = new List<Session>();
            m_reconnectHandlers = new List<SessionReconnectHandler>();
            m_activeServerServiceLevel = 0;
            m_validateResponse = validateResponse;
            m_output = writer;
            m_configuration = configuration;
            m_configuration.CertificateValidator.CertificateValidation += CertificateValidation;
        }
        #endregion

        #region IDisposable
        /// <summary>
        /// Dispose objects.
        /// </summary>
        public void Dispose()
        {
            Utils.SilentDispose(m_activeSession);
            m_configuration.CertificateValidator.CertificateValidation -= CertificateValidation;
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Action used 
        /// </summary>
        Action<IList, IList> ValidateResponse => m_validateResponse;

        /// <summary>
        /// Gets the application descriptions of the servers in the redundant server set.
        /// </summary>
        public ApplicationDescriptionCollection RedundantServerSet => m_redundantServerSet;

        /// <summary>
        /// The redundancy failover mode supported by the server.
        /// </summary>
        public RedundancySupport ConfiguredRedundancy => m_configuredRedundancy;

        /// <summary>
        /// Get the list of sessions associated with the client.
        /// </summary>
        public IList<Session> Sessions => m_sessions;

        /// <summary>
        /// Gets the active client session.
        /// </summary>
        public Session ActiveSession => m_activeSession;

        /// <summary>
        /// The session keepalive interval to be used in ms.
        /// </summary>
        public int KeepAliveInterval { get; set; } = 5000;

        /// <summary>
        /// The reconnect period to be used in ms.
        /// </summary>
        public int ReconnectPeriod { get; set; } = 10000;

        /// <summary>
        /// The session lifetime.
        /// </summary>
        public uint SessionLifeTime { get; set; } = 30 * 1000;

        /// <summary>
        /// The user identity to use to connect to the server.
        /// </summary>
        public IUserIdentity UserIdentity { get; set; } = new UserIdentity();

        /// <summary>
        /// Auto accept untrusted certificates.
        /// </summary>
        public bool AutoAccept { get; set; } = false;

        /// <summary>
        /// The file to use for log output.
        /// </summary>
        public string LogFile { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Creates a session with the UA server
        /// </summary>
        public async Task<bool> ConnectAsync(string serverUrl, bool useSecurity = true)
        {
            if (serverUrl == null) throw new ArgumentNullException(nameof(serverUrl));

            try
            {
                if (m_activeSession != null && m_activeSession.Connected == true)
                {
                    m_output.WriteLine("Session already connected!");
                }
                else
                {
                    m_output.WriteLine("Connecting to... {0}", serverUrl);

                    Session session = await SelectEndpointAndCreateSession(serverUrl, useSecurity);

                    // Assign the created session
                    if (session != null && session.Connected)
                    {
                        m_configuredRedundancy = ReadRedundancyConfiguration(session);

                        m_activeSession = session;
                        // override keep alive interval
                        m_activeSession.KeepAliveInterval = KeepAliveInterval;
                        // set up keep alive callback.
                        m_activeSession.KeepAlive += Session_KeepAlive;

                        if (m_configuredRedundancy != RedundancySupport.None)
                        {
                            SetupRedundancy(useSecurity);
                        }
                    }

                    // Session created successfully.
                    m_output.WriteLine("New Session Created with SessionName = {0}", m_activeSession.SessionName);
                }

                return true;
            }
            catch (Exception ex)
            {
                // Log Error
                m_output.WriteLine("Create Session Error : {0}", ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Disconnects the session.
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (m_activeSession != null)
                {
                    m_output.WriteLine("Disconnecting...");

                    lock (m_lock)
                    {
                        m_activeSession.KeepAlive -= Session_KeepAlive;
                        foreach(SessionReconnectHandler reconnectHandler in m_reconnectHandlers)
                        {
                            reconnectHandler.Dispose();
                        }
                    }

                    m_activeSession.Close();
                    m_activeSession.Dispose();
                    m_activeSession = null;
                    m_reconnectHandlers.Clear();

                    // Log Session Disconnected event
                    m_output.WriteLine("Session Disconnected.");
                }
                else
                {
                    m_output.WriteLine("Session not created!");
                }
            }
            catch (Exception ex)
            {
                // Log Error
                m_output.WriteLine($"Disconnect Error : {ex.Message}");
            }
        }
        #endregion

        #region Protected Methods
        /// <summary>
        /// Handles the certificate validation event.
        /// This event is triggered every time an untrusted certificate is received from the server.
        /// </summary>
        protected virtual void CertificateValidation(CertificateValidator sender, CertificateValidationEventArgs e)
        {
            bool certificateAccepted = false;

            // ****
            // Implement a custom logic to decide if the certificate should be
            // accepted or not and set certificateAccepted flag accordingly.
            // The certificate can be retrieved from the e.Certificate field
            // ***

            ServiceResult error = e.Error;
            m_output.WriteLine(error);
            if (error.StatusCode == StatusCodes.BadCertificateUntrusted && AutoAccept)
            {
                certificateAccepted = true;
            }

            if (certificateAccepted)
            {
                m_output.WriteLine("Untrusted Certificate accepted. Subject = {0}", e.Certificate.Subject);
                e.Accept = true;
            }
            else
            {
                m_output.WriteLine("Untrusted Certificate rejected. Subject = {0}", e.Certificate.Subject);
            }
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Handles a keep alive event from a session and triggers a failover or reconnect if necessary.
        /// </summary>
        private async void Session_KeepAlive(ISession session, KeepAliveEventArgs e)
        {
            try
            {
                // check for events from discarded sessions.
                if (!Object.ReferenceEquals(session, m_activeSession) && !m_sessions.Any(storedSession => Object.ReferenceEquals(session, storedSession)))
                {
                    return;
                }

                // start reconnect sequence on communication error.
                if (ServiceResult.IsBad(e.Status))
                {
                    // failover to redundant server if connection with active server is lost.
                    if (Object.ReferenceEquals(session, m_activeSession))
                    {
                        if (ConfiguredRedundancy == RedundancySupport.Cold)
                        {
                            Utils.LogInfo("COLD REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");
                            m_output.WriteLine("COLD REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");

                            string uriScheme = new Uri(session.Endpoint.EndpointUrl).Scheme;
                            ApplicationDescriptionCollection otherServers = m_redundantServerSet.Where(server => server.ApplicationUri != session.Endpoint.Server.ApplicationUri).ToArray();
                            foreach (ApplicationDescription server in otherServers)
                            {
                                string discoveryUrl = server.DiscoveryUrls.FirstOrDefault(url => new Uri(url).Scheme == uriScheme);

                                Session newSession = await SelectEndpointAndCreateSession(discoveryUrl, false);

                                if (newSession != null && newSession.Connected)
                                {
                                    foreach (Subscription subscription in session.Subscriptions)
                                    {
                                        Subscription copy = new Subscription(subscription, true);
                                        newSession.AddSubscription(copy);
                                        copy.Create();
                                        copy.ApplyChanges();
                                    }

                                    m_activeSession = newSession;
                                    // override keep alive interval
                                    m_activeSession.KeepAliveInterval = KeepAliveInterval;
                                    // set up keep alive callback.
                                    m_activeSession.KeepAlive += Session_KeepAlive;

                                    m_output.WriteLine("Failover succeeded.");
                                }
                            }
                        }
                        else if (ConfiguredRedundancy == RedundancySupport.Warm)
                        {
                            Utils.LogInfo("WARM REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");
                            m_output.WriteLine("WARM REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");

                            Session connectedStandbySession = m_sessions
                                .FirstOrDefault(storedSession => !Object.ReferenceEquals(storedSession, session)
                                    && storedSession.Connected
                                    && !m_reconnectHandlers.Any(reconnectHandler => Object.ReferenceEquals(reconnectHandler.Session, storedSession)));
                            if (connectedStandbySession != null)
                            {
                                m_activeSession = connectedStandbySession;
                                foreach (Subscription subscription in m_activeSession.Subscriptions)
                                {
                                    subscription.SetMonitoringMode(MonitoringMode.Reporting, subscription.MonitoredItems.ToList());
                                    subscription.SetPublishingMode(true);
                                }

                                m_output.WriteLine("Failover succeeded.");
                            }
                            else
                            {
                                m_output.WriteLine("Failover failed.");
                            }
                        }
                        else if (ConfiguredRedundancy == RedundancySupport.Hot)
                        {
                            Utils.LogInfo("HOT REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");
                            m_output.WriteLine("HOT REDUNDANCY: Connection with primary server was lost. Failing over to a redundant server...");

                            Session connectedStandbySession = m_sessions
                                .FirstOrDefault(storedSession => !Object.ReferenceEquals(storedSession, session)
                                    && storedSession.Connected
                                    && !m_reconnectHandlers.Any(reconnectHandler => Object.ReferenceEquals(reconnectHandler.Session, storedSession)));
                            if (connectedStandbySession != null)
                            {
                                m_activeSession = connectedStandbySession;
                                foreach (Subscription subscription in m_activeSession.Subscriptions)
                                {
                                    subscription.SetPublishingMode(true);
                                }

                                m_output.WriteLine("Failover succeeded.");
                            }
                            else
                            {
                                m_output.WriteLine("Failover failed.");
                            }
                        }
                    }

                    // start reconnect sequence.
                    if (ReconnectPeriod <= 0)
                    {
                        Utils.LogWarning("KeepAlive status {0}, but reconnect is disabled.", e.Status);
                    }
                    else
                    {
                        lock (m_lock)
                        {
                            if (!m_reconnectHandlers.Any(reconnectHandler => Object.ReferenceEquals(reconnectHandler.Session, session)))
                            {
                                Utils.LogInfo("KeepAlive status {0}, reconnecting in {1}ms.", e.Status, ReconnectPeriod);
                                m_output.WriteLine("--- RECONNECTING {0} ---", e.Status);
                                SessionReconnectHandler reconnectHandler = new SessionReconnectHandler(true);
                                reconnectHandler.BeginReconnect(session, ReconnectPeriod, Client_ReconnectComplete);
                                m_reconnectHandlers.Add(reconnectHandler);
                            }
                            else
                            {
                                Utils.LogInfo("KeepAlive status {0}, reconnect in progress.", e.Status);
                            }
                        }
                    }

                    return;
                }
            }
            catch (Exception exception)
            {
                Utils.LogError(exception, "Error in OnKeepAlive.");
            }
        }

        /// <summary>
        /// Called when the reconnect attempt was successful.
        /// </summary>
        private void Client_ReconnectComplete(object sender, EventArgs e)
        {
            // ignore callbacks from discarded objects.
            if (!m_reconnectHandlers.Any(reconnectHandler => Object.ReferenceEquals(sender, reconnectHandler)))
            {
                return;
            }

            lock (m_lock)
            {
                SessionReconnectHandler reconnectHandler = sender as SessionReconnectHandler;

                // if session recovered, Session property is null
                if (reconnectHandler.Session != null)
                {
                    Session oldSession = reconnectHandler.OldSession as Session;
                    Session newSession = reconnectHandler.Session as Session;

                    if (Object.ReferenceEquals(m_activeSession, oldSession))
                    {
                        m_activeSession = newSession;
                    }
                    else
                    {
                        int sessionIndex = m_sessions.IndexOf(oldSession);
                        if (sessionIndex != -1)
                        {
                            m_sessions[sessionIndex] = newSession;
                        }
                    }
                }

                reconnectHandler.Dispose();
                m_reconnectHandlers.Remove(reconnectHandler);
            }

            m_output.WriteLine("--- RECONNECTED ---");
        }

        /// <summary>
        /// Reads redundant server set and performs redundancy setup actions according to failover mode.
        /// </summary>
        /// <param name="useSecurity">If set to <c>true</c> select an endpoint that uses security.</param>
        private async void SetupRedundancy(bool useSecurity = true)
        {
            // Get the descriptions of the servers in the redundant server set.
            m_redundantServerSet = CoreClientUtils.FindServers(m_configuration, m_activeSession.Endpoint.EndpointUrl, null);

            // Create sessions with redundant servers for warm and hot failover modes.
            // And set server with highest service level as active server.
            if (m_configuredRedundancy == RedundancySupport.Warm || m_configuredRedundancy == RedundancySupport.Hot)
            {
                m_activeServerServiceLevel = ReadServiceLevel(m_activeSession);
                m_sessions.Add(m_activeSession);

                // Skip the active server.
                ApplicationDescriptionCollection otherServers = m_redundantServerSet.Where(server => server.ApplicationUri != m_activeSession.Endpoint.Server.ApplicationUri).ToArray();

                string uriScheme = new Uri(m_activeSession.Endpoint.EndpointUrl).Scheme;
                foreach (ApplicationDescription server in otherServers)
                {
                    string discoveryUrl = server.DiscoveryUrls.FirstOrDefault(url => new Uri(url).Scheme == uriScheme);

                    Session session = await SelectEndpointAndCreateSession(discoveryUrl, useSecurity);

                    // Set the session as the active one if its service level is higher
                    if (session != null && session.Connected)
                    {
                        byte serviceLevel = ReadServiceLevel(session);
                        session.KeepAliveInterval = KeepAliveInterval;
                        session.KeepAlive += Session_KeepAlive;
                        if (serviceLevel > m_activeServerServiceLevel)
                        {
                            m_activeServerServiceLevel = serviceLevel;
                            m_activeSession = session;
                        }

                        m_sessions.Add(session);
                    }
                }
            }
        }

        /// <summary>
        /// Selects the endpoint that best matches the current settings and uses it to create a session.
        /// </summary>
        /// <param name="discoveryUrl">The discovery URL of the server.</param>
        /// <param name="useSecurity">If set to <c>true</c> select an endpoint that uses security.</param>
        /// <returns>The created session.</returns>
        private async Task<Session> SelectEndpointAndCreateSession(string discoveryUrl, bool useSecurity = true)
        {
            EndpointDescription endpointDescription = CoreClientUtils.SelectEndpoint(m_configuration, discoveryUrl, useSecurity);
            EndpointConfiguration endpointConfiguration = EndpointConfiguration.Create(m_configuration);
            ConfiguredEndpoint endpoint = new ConfiguredEndpoint(null, endpointDescription, endpointConfiguration);

            return await Opc.Ua.Client.Session.Create(
                m_configuration,
                endpoint,
                false,
                false,
                m_configuration.ApplicationName,
                SessionLifeTime,
                UserIdentity,
                null
            ).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads the RedundancySupport property value from the server.
        /// </summary>
        /// <param name="session">The session to use.</param>
        /// <returns>The RedundancySupport value.</returns>
        private RedundancySupport ReadRedundancyConfiguration(Session session)
        {
            ReadValueIdCollection nodesToRead = new ReadValueIdCollection {
                new ReadValueId { NodeId = VariableIds.Server_ServerRedundancy_RedundancySupport, AttributeId = Attributes.Value }
            };

            session.Read(
                    null,
                    0,
                    TimestampsToReturn.Both,
                    nodesToRead,
                    out DataValueCollection resultsValues,
                    out DiagnosticInfoCollection diagnosticInfos
                );

            m_validateResponse(resultsValues, nodesToRead);

            return (RedundancySupport)resultsValues[0].Value;
        }

        /// <summary>
        /// Reads the ServiceLevel property value from the server.
        /// </summary>
        /// <param name="session">The session to use.</param>
        /// <returns>The ServiceLevel value.</returns>
        private byte ReadServiceLevel(Session session)
        {
            ReadValueIdCollection nodesToRead = new ReadValueIdCollection {
                new ReadValueId { NodeId = VariableIds.Server_ServiceLevel, AttributeId = Attributes.Value }
            };

            session.Read(
                    null,
                    0,
                    TimestampsToReturn.Both,
                    nodesToRead,
                    out DataValueCollection resultsValues,
                    out DiagnosticInfoCollection diagnosticInfos
                );

            m_validateResponse(resultsValues, nodesToRead);

            return (byte)resultsValues[0].Value;
        }
        #endregion

        #region Private Fields
        private object m_lock = new object();
        private ApplicationConfiguration m_configuration;        
        private IList<SessionReconnectHandler> m_reconnectHandlers;
        private ApplicationDescriptionCollection m_redundantServerSet;
        private RedundancySupport m_configuredRedundancy;
        private IList<Session> m_sessions;
        private Session m_activeSession;
        private byte m_activeServerServiceLevel;
        private readonly TextWriter m_output;
        private readonly Action<IList, IList> m_validateResponse;
        #endregion
    }
}
