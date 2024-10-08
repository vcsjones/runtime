// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Microsoft.Extensions.Primitives;

namespace Microsoft.Extensions.Configuration
{
    /// <summary>
    /// Defines the core behavior of configuration providers and provides a base for derived classes.
    /// </summary>
    public abstract class ConfigurationProvider : IConfigurationProvider
    {
        private ConfigurationReloadToken _reloadToken = new ConfigurationReloadToken();

        /// <summary>
        /// Initializes a new <see cref="IConfigurationProvider"/>.
        /// </summary>
        protected ConfigurationProvider()
        {
            Data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets or sets the configuration key-value pairs for this provider.
        /// </summary>
        protected IDictionary<string, string?> Data { get; set; }

        /// <summary>
        /// Attempts to find a value with the given key.
        /// </summary>
        /// <param name="key">The key to lookup.</param>
        /// <param name="value">When this method returns, contains the value if one is found.</param>
        /// <returns><see langword="true" /> if <paramref name="key" /> has a value; otherwise <see langword="false" />.</returns>
        public virtual bool TryGet(string key, out string? value)
            => Data.TryGetValue(key, out value);

        /// <summary>
        /// Sets a value for a given key.
        /// </summary>
        /// <param name="key">The configuration key to set.</param>
        /// <param name="value">The value to set.</param>
        public virtual void Set(string key, string? value)
            => Data[key] = value;

        /// <summary>
        /// Loads (or reloads) the data for this provider.
        /// </summary>
        public virtual void Load()
        { }

        /// <summary>
        /// Returns the list of keys that this provider has.
        /// </summary>
        /// <param name="earlierKeys">The earlier keys that other providers contain.</param>
        /// <param name="parentPath">The path for the parent IConfiguration.</param>
        /// <returns>The list of keys for this provider.</returns>
        public virtual IEnumerable<string> GetChildKeys(
            IEnumerable<string> earlierKeys,
            string? parentPath)
        {
            var results = new List<string>();

            if (parentPath is null)
            {
                foreach (KeyValuePair<string, string?> kv in Data)
                {
                    results.Add(Segment(kv.Key, 0));
                }
            }
            else
            {
                Debug.Assert(ConfigurationPath.KeyDelimiter == ":");

                foreach (KeyValuePair<string, string?> kv in Data)
                {
                    if (kv.Key.Length > parentPath.Length &&
                        kv.Key.StartsWith(parentPath, StringComparison.OrdinalIgnoreCase) &&
                        kv.Key[parentPath.Length] == ':')
                    {
                        results.Add(Segment(kv.Key, parentPath.Length + 1));
                    }
                }
            }

            results.AddRange(earlierKeys);

            results.Sort(ConfigurationKeyComparer.Comparison);

            return results;
        }

        private static string Segment(string key, int prefixLength)
        {
            Debug.Assert(ConfigurationPath.KeyDelimiter == ":");
            int indexOf = key.IndexOf(':', prefixLength);
            return indexOf < 0 ? key.Substring(prefixLength) : key.Substring(prefixLength, indexOf - prefixLength);
        }

        /// <summary>
        /// Returns a <see cref="IChangeToken"/> that can be used to listen when this provider is reloaded.
        /// </summary>
        /// <returns>The <see cref="IChangeToken"/>.</returns>
        public IChangeToken GetReloadToken()
        {
            return _reloadToken;
        }

        /// <summary>
        /// Triggers the reload change token and creates a new one.
        /// </summary>
        protected void OnReload()
        {
            ConfigurationReloadToken previousToken = Interlocked.Exchange(ref _reloadToken, new ConfigurationReloadToken());
            previousToken.OnReload();
        }

        /// <summary>
        /// Generates a string representing this provider name and relevant details.
        /// </summary>
        /// <returns>The configuration name.</returns>
        public override string ToString() => GetType().Name;
    }
}
