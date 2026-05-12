pragma solidity ^0.8.0;

contract KubeAuth {
    mapping(address => bool) public authorizedUsers;

    function addUser(address user) public {
        authorizedUsers[user] = true;
    }

    function checkAccess(address user) public view returns(bool) {
        return authorizedUsers[user];
    }
}
