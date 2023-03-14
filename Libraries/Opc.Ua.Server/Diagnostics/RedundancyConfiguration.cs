using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Opc.Ua;

namespace Opc.Ua.Server
{
    /// <summary>
    /// Stores the configuration for non transparent server redundancy.
    /// </summary>
    [DataContract(Namespace = "http://samples.org/UA/Redundancy")]
    public class RedundancyConfiguration
    {
        #region Constructors
        /// <summary>
        /// The default constructor.
        /// </summary>
        public RedundancyConfiguration()
        {
            Initialize();
        }

        /// <summary>
        /// Initializes the object during deserialization.
        /// </summary>
        [OnDeserializing()]
        private void Initialize(StreamingContext context)
        {
            Initialize();
        }

        /// <summary>
        /// Sets private members to default values.
        /// </summary>
        private void Initialize()
        {

        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Stores the non transparent redundancy settings to be exposed in the server object.
        /// </summary>
        [DataMember(IsRequired = true, EmitDefaultValue = false, Order = 0)]
        public RedundancySettings RedundancySettings
        {
            get { return m_redundancySettings; }
            set { m_redundancySettings = value; }
        }

        /// <summary>
        /// List of application descriptions of other servers in the redundant server set.
        /// </summary>
        [DataMember(IsRequired = true, EmitDefaultValue = false, Order = 1)]
        public ApplicationDescriptionCollection RedundantServersDescriptions
        {
            get { return m_redundantServersDescriptions; }
            set { m_redundantServersDescriptions = value; }
        }
        #endregion

        #region Private Members
        private RedundancySettings m_redundancySettings;
        private ApplicationDescriptionCollection m_redundantServersDescriptions;
        #endregion
    }

    /// <summary>
    /// Stores the non transparent redundancy settings to be exposed in the server object.
    /// </summary>
    [DataContract(Namespace = "http://samples.org/UA/Redundancy")]
    public class RedundancySettings
    {
        #region Constructors
        /// <summary>
        /// The default constructor.
        /// </summary>
        public RedundancySettings()
        {
            Initialize();
        }

        /// <summary>
        /// Initializes the object during deserialization.
        /// </summary>
        [OnDeserializing()]
        private void Initialize(StreamingContext context)
        {
            Initialize();
        }

        /// <summary>
        /// Sets private members to default values.
        /// </summary>
        private void Initialize()
        {

        }
        #endregion

        #region Public Properties
        /// <summary>
        /// Type of redundancy support: Cold, Warm, Hot, HotAndMirrored.
        /// </summary>
        [DataMember(IsRequired = true, EmitDefaultValue = false, Order = 0)]
        public RedundancySupport RedundancySupport
        {
            get { return m_redundancySupport; }
            set { m_redundancySupport = value; }
        }

        /// <summary>
        /// List of URIs of the servers in the same redundancy group.
        /// </summary>
        [DataMember(IsRequired = true, EmitDefaultValue = false, Order = 1)]
        public ServerUriCollection ServerUriArray
        {
            get { return m_serverUriArray; }
            set { m_serverUriArray = value; }
        }
        #endregion

        #region Private Members
        private RedundancySupport m_redundancySupport;
        private ServerUriCollection m_serverUriArray;
        #endregion
    }

    /// <summary>
    /// A collection of server URIs
    /// </summary>
    [CollectionDataContract(ItemName = "ServerUri", Namespace = "http://samples.org/UA/Redundancy")]
    public class ServerUriCollection : List<string>
    {

    }
}
