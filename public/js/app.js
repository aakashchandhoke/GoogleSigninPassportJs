var app = angular.module('PassportApp', ['ngRoute']);

app.config(function($routeProvider, $httpProvider){
    $routeProvider
        .when('/', {
            templateUrl: '/views/home/home.html',
           // controller: 'MainCtrl',
        })
        .when('/profile', {
            templateUrl: 'views/profile/profile.html',
           // controller: 'AdminCtrl',
            resolve: {
                 loggedin: checkLoggedin
            }
        })
        .when('/login', {
            templateUrl: 'views/login/login.html',
            controller: 'LoginCtrl'
        })
        .when('/register', {
            templateUrl: 'views/register/register.html',
            controller: 'RegisterCtrl'
        })
        .otherwise({
            redirectTo: '/'
        });

    /*$httpProvider
    .interceptors
    .push(function($q, $location)
    {
        return {
            response: function(response)
            { 
                return response;
            },
            responseError: function(response)
            {
                if (response.status === 401)
                    $location.url('/login');
                return $q.reject(response);
            }
        };
    });*/ 
});

var checkLoggedin = function($q, $timeout, $http, $location, $rootScope)
{
    var deferred = $q.defer();

    $http.get('/loggedin').success(function(user)
    {
        $rootScope.errorMessage = null;
        // User is Authenticated
        if (user !== '0')
            deferred.resolve();
        // User is Not Authenticated
        else
        {
            $rootScope.errorMessage = 'You need to log in.';
            deferred.reject();
            $location.url('/login');
        }
    });
    
    return deferred.promise;
};

app.controller('NavCtrl',function($scope,$http,$location){
    $scope.logout=function(){
        $http.post("/logout")
        .success(function(){
            $location.url("/home");
        })
    }
    
});