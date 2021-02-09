using System;

namespace AspNet.Security.OAuth.SingPass
{
    public class SingPassAuthenticationException : Exception
    {
        public SingPassAuthenticationException()
        {
        }
        public SingPassAuthenticationException(string message) : base(message)
        {
        }
        public SingPassAuthenticationException(Exception e, string message) : base(message, e)
        {

        }
    }
}
