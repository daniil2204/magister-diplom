/*
 * Fixed version of smartbugs-curated reentrancy/0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
 * (pair, fix style: cei).
 * Fix: in WithdrawToHolder the holder balance is debited BEFORE the external call
 * (checks-effects-interactions), so no state write remains after the call and the SC08 target
 * disappears. Only the SC08 unit is scored on this version.
 * solc version inherited from the original (0.4.x).
 */

pragma solidity ^0.4.19;

contract Ownable
{
    address newOwner;
    address owner = msg.sender;

    function changeOwner(address addr)
    public
    onlyOwner
    {
        newOwner = addr;
    }

    function confirmOwner()
    public
    {
        if(msg.sender==newOwner)
        {
            owner=newOwner;
        }
    }

    modifier onlyOwner
    {
        if(owner == msg.sender)_;
    }
}

contract Token is Ownable
{
    address owner = msg.sender;
    function WithdrawToken(address token, uint256 amount,address to)
    public
    onlyOwner
    {
        token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);
    }
}

contract TokenBank is Token
{
    uint public MinDeposit;
    mapping (address => uint) public Holders;

     ///Constructor
    function initTokenBank()
    public
    {
        owner = msg.sender;
        MinDeposit = 1 ether;
    }

    function()
    payable
    {
        Deposit();
    }

    function Deposit()
    payable
    {
        if(msg.value>MinDeposit)
        {
            Holders[msg.sender]+=msg.value;
        }
    }

    function WitdrawTokenToHolder(address _to,address _token,uint _amount)
    public
    onlyOwner
    {
        if(Holders[_to]>0)
        {
            Holders[_to]=0;
            WithdrawToken(_token,_amount,_to);
        }
    }

    function WithdrawToHolder(address _addr, uint _wei)
    public
    onlyOwner
    payable
    {
        if(Holders[_addr]>0)
        {
            // effects before interaction: debit first, then call
            Holders[_addr]-=_wei;
            _addr.call.value(_wei)();
        }
    }
}
