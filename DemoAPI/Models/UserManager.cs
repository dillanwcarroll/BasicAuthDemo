using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DemoAPI.Models
{
    public class UserManager
    {
        private DemoDBEntities _Context;

        public UserManager()
        {
            _Context = new DemoDBEntities();
        }

        public bool ValidateUser(string userName, string Password)
        {
            var result = _Context.UserMasters.SingleOrDefault(x => x.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase)
                                                                    && x.Password == Password);
            return result != null? true:false;
        }
    }
}