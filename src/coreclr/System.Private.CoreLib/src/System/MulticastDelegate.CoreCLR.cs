// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Threading;

namespace System
{
    [ClassInterface(ClassInterfaceType.None)]
    [ComVisible(true)]
    public abstract partial class MulticastDelegate : Delegate
    {
        // This is set under 2 circumstances
        // 1. Multicast delegate
        // 2. Wrapper delegate
        private object? _invocationList; // Initialized by VM as needed
        private nint _invocationCount;

        internal bool IsUnmanagedFunctionPtr()
        {
            return _invocationCount == -1;
        }

        internal bool InvocationListLogicallyNull()
        {
            return (_invocationList == null) || (_invocationList is LoaderAllocator) || (_invocationList is DynamicResolver);
        }

        [Obsolete(Obsoletions.LegacyFormatterImplMessage, DiagnosticId = Obsoletions.LegacyFormatterImplDiagId, UrlFormat = Obsoletions.SharedUrlFormat)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            throw new SerializationException(SR.Serialization_DelegatesNotSupported);
        }

        // equals returns true IIF the delegate is not null and has the
        //    same target, method and invocation list as this object
        public sealed override bool Equals([NotNullWhen(true)] object? obj)
        {
            if (obj == null)
                return false;
            if (ReferenceEquals(this, obj))
                return true;
            if (!InternalEqualTypes(this, obj))
                return false;

            // Since this is a MulticastDelegate and we know
            // the types are the same, obj should also be a
            // MulticastDelegate
            Debug.Assert(obj is MulticastDelegate, "Shouldn't have failed here since we already checked the types are the same!");
            MulticastDelegate d = Unsafe.As<MulticastDelegate>(obj);

            if (_invocationCount != 0)
            {
                // there are 4 kind of delegate kinds that fall into this bucket
                // 1- Multicast (_invocationList is Object[])
                // 2- Wrapper (_invocationList is Delegate)
                // 3- Unmanaged FntPtr (_invocationList == null)
                // 4- Open virtual (_invocationCount == MethodDesc of target, _invocationList == null, LoaderAllocator, or DynamicResolver)

                if (InvocationListLogicallyNull())
                {
                    if (IsUnmanagedFunctionPtr())
                    {
                        if (!d.IsUnmanagedFunctionPtr())
                            return false;

                        return _methodPtr == d._methodPtr
                            && _methodPtrAux == d._methodPtrAux;
                    }

                    // now we know 'this' is not a special one, so we can work out what the other is
                    if (d._invocationList is Delegate)
                        // this is a wrapper delegate so we need to unwrap and check the inner one
                        return Equals(d._invocationList);

                    return base.Equals(obj);
                }
                else
                {
                    if (_invocationList is Delegate invocationListDelegate)
                    {
                        // this is a wrapper delegate so we need to unwrap and check the inner one
                        return invocationListDelegate.Equals(obj);
                    }
                    else
                    {
                        Debug.Assert(_invocationList is object[], "empty invocation list on multicast delegate");
                        return InvocationListEquals(d);
                    }
                }
            }
            else
            {
                // among the several kind of delegates falling into this bucket one has got a non
                // empty _invocationList (open static with special sig)
                // to be equals we need to check that _invocationList matches (both null is fine)
                // and call the base.Equals()
                if (!InvocationListLogicallyNull())
                {
                    if (!_invocationList!.Equals(d._invocationList))
                        return false;
                    return base.Equals(d);
                }

                // now we know 'this' is not a special one, so we can work out what the other is
                if (d._invocationList is Delegate)
                    // this is a wrapper delegate so we need to unwrap and check the inner one
                    return Equals(d._invocationList);

                // now we can call on the base
                return base.Equals(d);
            }
        }

        // Recursive function which will check for equality of the invocation list.
        private bool InvocationListEquals(MulticastDelegate d)
        {
            Debug.Assert(d != null);
            Debug.Assert(_invocationList is object[]);
            object[] invocationList = (object[])_invocationList;

            if (d._invocationCount != _invocationCount)
                return false;

            int invocationCount = (int)_invocationCount;
            for (int i = 0; i < invocationCount; i++)
            {
                Debug.Assert(invocationList[i] is Delegate);
                Delegate dd = (Delegate)invocationList[i]; // If invocationList is an object[], it always contains Delegate (or MulticastDelegate) objects

                object[] dInvocationList = (d._invocationList as object[])!;
                if (!dd.Equals(dInvocationList[i]))
                    return false;
            }
            return true;
        }

        private static bool TrySetSlot(object?[] a, int index, object o)
        {
            if (a[index] == null && Interlocked.CompareExchange(ref a[index], o, null) == null)
                return true;

            // The slot may be already set because we have added and removed the same method before.
            // Optimize this case, because it's cheaper than copying the array.
            if (a[index] is object ai)
            {
                MulticastDelegate d = (MulticastDelegate)o;
                MulticastDelegate dd = (MulticastDelegate)ai;

                if (dd._methodPtr == d._methodPtr &&
                    dd._target == d._target &&
                    dd._methodPtrAux == d._methodPtrAux)
                {
                    return true;
                }
            }
            return false;
        }

        private unsafe MulticastDelegate NewMulticastDelegate(object[] invocationList, int invocationCount, bool thisIsMultiCastAlready)
        {
            // First, allocate a new multicast delegate just like this one, i.e. same type as the this object
            MulticastDelegate result = Unsafe.As<MulticastDelegate>(RuntimeTypeHandle.InternalAllocNoChecks(RuntimeHelpers.GetMethodTable(this)));

            // Performance optimization - if this already points to a true multicast delegate,
            // copy _methodPtr and _methodPtrAux fields rather than calling into the EE to get them
            if (thisIsMultiCastAlready)
            {
                result._methodPtr = this._methodPtr;
                result._methodPtrAux = this._methodPtrAux;
            }
            else
            {
                result._methodPtr = GetMulticastInvoke();
                result._methodPtrAux = GetInvokeMethod();
            }
            result._target = result;
            result._invocationList = invocationList;
            result._invocationCount = invocationCount;

            return result;
        }

        internal MulticastDelegate NewMulticastDelegate(object[] invocationList, int invocationCount)
        {
            return NewMulticastDelegate(invocationList, invocationCount, false);
        }

        internal void StoreDynamicMethod(MethodInfo dynamicMethod)
        {
            if (_invocationCount != 0)
            {
                Debug.Assert(!IsUnmanagedFunctionPtr(), "dynamic method and unmanaged fntptr delegate combined");
                // must be a secure/wrapper one, unwrap and save
                MulticastDelegate d = ((MulticastDelegate?)_invocationList)!;
                d._methodBase = dynamicMethod;
            }
            else
                _methodBase = dynamicMethod;
        }

        // This method will combine this delegate with the passed delegate
        //    to form a new delegate.
        protected sealed override Delegate CombineImpl(Delegate? follow)
        {
            if (follow is null)
                return this;

            // Verify that the types are the same...
            if (!InternalEqualTypes(this, follow))
                throw new ArgumentException(SR.Arg_DlgtTypeMis);

            MulticastDelegate dFollow = (MulticastDelegate)follow;
            object[]? resultList;
            int followCount = 1;
            object[]? followList = dFollow._invocationList as object[];
            if (followList != null)
                followCount = (int)dFollow._invocationCount;

            int resultCount;
            if (_invocationList is not object[] invocationList)
            {
                resultCount = 1 + followCount;
                resultList = new object[resultCount];
                resultList[0] = this;
                if (followList == null)
                {
                    resultList[1] = dFollow;
                }
                else
                {
                    for (int i = 0; i < followCount; i++)
                        resultList[1 + i] = followList[i];
                }
                return NewMulticastDelegate(resultList, resultCount);
            }
            else
            {
                int invocationCount = (int)_invocationCount;
                resultCount = invocationCount + followCount;
                resultList = null;
                if (resultCount <= invocationList.Length)
                {
                    resultList = invocationList;
                    if (followList == null)
                    {
                        if (!TrySetSlot(resultList, invocationCount, dFollow))
                            resultList = null;
                    }
                    else
                    {
                        for (int i = 0; i < followCount; i++)
                        {
                            if (!TrySetSlot(resultList, invocationCount + i, followList[i]))
                            {
                                resultList = null;
                                break;
                            }
                        }
                    }
                }

                if (resultList == null)
                {
                    int allocCount = invocationList.Length;
                    while (allocCount < resultCount)
                        allocCount *= 2;

                    resultList = new object[allocCount];

                    for (int i = 0; i < invocationCount; i++)
                        resultList[i] = invocationList[i];

                    if (followList == null)
                    {
                        resultList[invocationCount] = dFollow;
                    }
                    else
                    {
                        for (int i = 0; i < followCount; i++)
                            resultList[invocationCount + i] = followList[i];
                    }
                }
                return NewMulticastDelegate(resultList, resultCount, true);
            }
        }

        private object[] DeleteFromInvocationList(object[] invocationList, int invocationCount, int deleteIndex, int deleteCount)
        {
            Debug.Assert(_invocationList is object[]);
            object[] thisInvocationList = (object[])_invocationList;
            int allocCount = thisInvocationList.Length;
            while (allocCount / 2 >= invocationCount - deleteCount)
                allocCount /= 2;

            object[] newInvocationList = new object[allocCount];

            for (int i = 0; i < deleteIndex; i++)
                newInvocationList[i] = invocationList[i];

            for (int i = deleteIndex + deleteCount; i < invocationCount; i++)
                newInvocationList[i - deleteCount] = invocationList[i];

            return newInvocationList;
        }

        private static bool EqualInvocationLists(object[] a, object[] b, int start, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (!a[start + i].Equals(b[i]))
                    return false;
            }
            return true;
        }

        // This method currently looks backward on the invocation list
        //    for an element that has Delegate based equality with value.  (Doesn't
        //    look at the invocation list.)  If this is found we remove it from
        //    this list and return a new delegate.  If its not found a copy of the
        //    current list is returned.
        protected sealed override Delegate? RemoveImpl(Delegate value)
        {
            // There is a special case were we are removing using a delegate as
            //    the value we need to check for this case
            //
            MulticastDelegate? v = value as MulticastDelegate;

            if (v == null)
                return this;
            if (v._invocationList is not object[])
            {
                if (_invocationList is not object[] invocationList)
                {
                    // they are both not real Multicast
                    if (this.Equals(value))
                        return null;
                }
                else
                {
                    int invocationCount = (int)_invocationCount;
                    for (int i = invocationCount; --i >= 0;)
                    {
                        if (value.Equals(invocationList[i]))
                        {
                            if (invocationCount == 2)
                            {
                                // Special case - only one value left, either at the beginning or the end
                                return (Delegate)invocationList[1 - i];
                            }
                            else
                            {
                                object[] list = DeleteFromInvocationList(invocationList, invocationCount, i, 1);
                                return NewMulticastDelegate(list, invocationCount - 1, true);
                            }
                        }
                    }
                }
            }
            else
            {
                if (_invocationList is object[] invocationList)
                {
                    int invocationCount = (int)_invocationCount;
                    int vInvocationCount = (int)v._invocationCount;
                    for (int i = invocationCount - vInvocationCount; i >= 0; i--)
                    {
                        if (EqualInvocationLists(invocationList, (v._invocationList as object[])!, i, vInvocationCount))
                        {
                            if (invocationCount - vInvocationCount == 0)
                            {
                                // Special case - no values left
                                return null;
                            }
                            else if (invocationCount - vInvocationCount == 1)
                            {
                                // Special case - only one value left, either at the beginning or the end
                                return (Delegate)invocationList[i != 0 ? 0 : invocationCount - 1];
                            }
                            else
                            {
                                object[] list = DeleteFromInvocationList(invocationList, invocationCount, i, vInvocationCount);
                                return NewMulticastDelegate(list, invocationCount - vInvocationCount, true);
                            }
                        }
                    }
                }
            }

            return this;
        }

        // This method returns the Invocation list of this multicast delegate.
        public sealed override Delegate[] GetInvocationList()
        {
            Delegate[] del;
            if (_invocationList is not object[] invocationList)
            {
                del = new Delegate[1];
                del[0] = this;
            }
            else
            {
                // Create an array of delegate copies and each
                //    element into the array
                del = new Delegate[(int)_invocationCount];

                for (int i = 0; i < del.Length; i++)
                    del[i] = (Delegate)invocationList[i];
            }
            return del;
        }

        internal new bool HasSingleTarget => _invocationList is not object[];

        // Used by delegate invocation list enumerator
        internal object? /* Delegate? */ TryGetAt(int index)
        {
            if (_invocationList is not object[] invocationList)
            {
                return (index == 0) ? this : null;
            }
            else
            {
                return ((uint)index < (uint)_invocationCount) ? invocationList[index] : null;
            }
        }

        public sealed override int GetHashCode()
        {
            if (IsUnmanagedFunctionPtr())
                return HashCode.Combine(_methodPtr, _methodPtrAux);

            if (_invocationCount != 0)
            {
                if (_invocationList is Delegate t)
                {
                    // this is a wrapper delegate so we need to unwrap and check the inner one
                    return t.GetHashCode();
                }
            }

            if (_invocationList is not object[] invocationList)
            {
                return base.GetHashCode();
            }
            else
            {
                int hash = 0;
                for (int i = 0; i < (int)_invocationCount; i++)
                {
                    hash = hash * 33 + invocationList[i].GetHashCode();
                }

                return hash;
            }
        }

        internal override object? GetTarget()
        {
            if (_invocationCount != 0)
            {
                // _invocationCount != 0 we are in one of these cases:
                // - Multicast -> return the target of the last delegate in the list
                // - Wrapper delegate -> return the target of the inner delegate
                // - unmanaged function pointer - return null
                // - virtual open delegate - return null
                if (InvocationListLogicallyNull())
                {
                    // both open virtual and ftn pointer return null for the target
                    return null;
                }
                else
                {
                    if (_invocationList is object[] invocationList)
                    {
                        int invocationCount = (int)_invocationCount;
                        return ((Delegate)invocationList[invocationCount - 1]).GetTarget();
                    }
                    else
                    {
                        if (_invocationList is Delegate receiver)
                            return receiver.GetTarget();
                    }
                }
            }
            return base.GetTarget();
        }

        protected override MethodInfo GetMethodImpl()
        {
            if (_invocationCount != 0 && _invocationList != null)
            {
                // multicast case
                if (_invocationList is object[] invocationList)
                {
                    int index = (int)_invocationCount - 1;
                    return ((Delegate)invocationList[index]).Method;
                }

                if (_invocationList is MulticastDelegate innerDelegate)
                {
                    // must be a wrapper delegate
                    return innerDelegate.GetMethodImpl();
                }
            }
            else if (IsUnmanagedFunctionPtr())
            {
                // we handle unmanaged function pointers here because the generic ones (used for WinRT) would otherwise
                // be treated as open delegates by the base implementation, resulting in failure to get the MethodInfo
                if (_methodBase is MethodInfo methodInfo)
                {
                    return methodInfo;
                }

                IRuntimeMethodInfo method = FindMethodHandle();
                RuntimeType declaringType = RuntimeMethodHandle.GetDeclaringType(method);

                // need a proper declaring type instance method on a generic type
                if (declaringType.IsGenericType)
                {
                    // we are returning the 'Invoke' method of this delegate so use this.GetType() for the exact type
                    RuntimeType reflectedType = (RuntimeType)GetType();
                    declaringType = reflectedType;
                }

                _methodBase = (MethodInfo)RuntimeType.GetMethodBase(declaringType, method)!;
                return (MethodInfo)_methodBase;
            }

            // Otherwise, must be an inner delegate of a wrapper delegate of an open virtual method. In that case, call base implementation
            return base.GetMethodImpl();
        }

        // this should help inlining
        [DoesNotReturn]
        [DebuggerNonUserCode]
        private static void ThrowNullThisInDelegateToInstance() =>
            throw new ArgumentException(SR.Arg_DlgtNullInst);

#pragma warning disable IDE0060
        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorClosed(object target, IntPtr methodPtr)
        {
            if (target == null)
                ThrowNullThisInDelegateToInstance();
            this._target = target;
            this._methodPtr = methodPtr;
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorClosedStatic(object target, IntPtr methodPtr)
        {
            this._target = target;
            this._methodPtr = methodPtr;
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorRTClosed(object target, IntPtr methodPtr)
        {
            if (target == null)
                ThrowNullThisInDelegateToInstance();
            this._target = target;
            this._methodPtr = AdjustTarget(target, methodPtr);
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorOpened(object target, IntPtr methodPtr, IntPtr shuffleThunk)
        {
            this._target = this;
            this._methodPtr = shuffleThunk;
            this._methodPtrAux = methodPtr;
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorVirtualDispatch(object target, IntPtr methodPtr, IntPtr shuffleThunk)
        {
            this._target = this;
            this._methodPtr = shuffleThunk;
            this.InitializeVirtualCallStub(methodPtr);
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorCollectibleClosedStatic(object target, IntPtr methodPtr, IntPtr gchandle)
        {
            this._target = target;
            this._methodPtr = methodPtr;
            this._methodBase = GCHandle.InternalGet(gchandle);
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorCollectibleOpened(object target, IntPtr methodPtr, IntPtr shuffleThunk, IntPtr gchandle)
        {
            this._target = this;
            this._methodPtr = shuffleThunk;
            this._methodPtrAux = methodPtr;
            this._methodBase = GCHandle.InternalGet(gchandle);
        }

        [DebuggerNonUserCode]
        [DebuggerStepThrough]
        private void CtorCollectibleVirtualDispatch(object target, IntPtr methodPtr, IntPtr shuffleThunk, IntPtr gchandle)
        {
            this._target = this;
            this._methodPtr = shuffleThunk;
            this._methodBase = GCHandle.InternalGet(gchandle);
            this.InitializeVirtualCallStub(methodPtr);
        }
#pragma warning restore IDE0060
    }
}
