app.controller('RegisterCtrl', function($scope, $http, $location,$rootScope)
{
    $scope.register = function(user)
    {
        if(user.password==user.password2)
        {
         $http.post('/register', user)
        .success(function(response)
        {
            console.log(response);
            $rootScope.currentUser=response;
            $location.url("/profile");
        });
        }
        else
        {
            console.log('password dont match');
        }
    }
});