using System;
using System.Collections.Generic;

namespace CryptStr2.Utils
{
    public static class Equality<T>
    {

        public static IEqualityComparer<T> Create<K>(Func<T, K> keySelector, IEqualityComparer<K> comparer = null)
        {
            if (keySelector == null)
            {
                throw new ArgumentNullException(nameof(keySelector));
            }

            return new Internal_EqualityComparer<K>(keySelector, comparer);
        }

        private class Internal_EqualityComparer<K> : IEqualityComparer<T>
        {
            private Func<T, K> _keySelector = null;
            private IEqualityComparer<K> _comparer = null;

            public Internal_EqualityComparer(Func<T, K> keySelector, IEqualityComparer<K> comparer = null)
            {
                this._keySelector = keySelector;
                this._comparer = comparer ?? EqualityComparer<K>.Default;
            }

            public bool Equals(T x, T y)
            {
                return this._comparer.Equals(this._keySelector(x), this._keySelector(y));
            }

            public int GetHashCode(T obj)
            {
                return this._comparer.GetHashCode(this._keySelector(obj));
            }
        }
    }
}
