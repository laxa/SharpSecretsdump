using System;
using System.Collections.Generic;
using System.Text;
using System.Collections;

namespace SharpSecretsdump.lib.Kerberos
{
    public static class ArrayUtility
    {
        /// <summary>
        /// Gets a sub array from an array.
        /// </summary>
        /// <typeparam name="T">The type of array.</typeparam>
        /// <param name="array">The original array.</param>
        /// <param name="startIndex">The start index to copy.</param>
        /// <param name="length">The length of sub array.</param>
        /// <exception cref="ArgumentException">Raised when startIndex or startIndex plus the length of 
        /// sub array exceeds the range of original array.</exception>
        /// <returns>The sub array.</returns>
        public static T[] SubArray<T>(T[] array, int startIndex, int length)
        {
            T[] subArray = new T[length];
            Array.Copy(array, startIndex, subArray, 0, length);

            return subArray;
        }

        /// <summary>
        /// Gets a sub array from an array. With given start index, it will return the rest of the array.
        /// </summary>
        /// <typeparam name="T">The type of array.</typeparam>
        /// <param name="array">The original array.</param>
        /// <param name="startIndex">The start index to copy.</param>
        /// <exception cref="ArgumentException">Raised when startIndex or startIndex plus the length of 
        /// sub array exceeds the range of original array.</exception>
        /// <returns>The sub array.</returns>
        public static T[] SubArray<T>(T[] array, int startIndex)
        {
            return SubArray<T>(array, startIndex, array.Length - startIndex);
        }
    }
}
