/*
 * Fixed version of smartbugs-curated reentrancy/0x561eac93c92360949ab1f1403323e6db345cbf31.sol
 * (pair, fix style: cei).
 * Fix: in Collect the balance is debited BEFORE the external call (checks-effects-interactions),
 * so no state write remains after the call and the SC08 target disappears. Only the SC08 unit is
 * scored on this version.
 * solc version inherited from the original (0.4.x).
 */

pragma solidity ^0.4.19;

contract BANK_SAFE
{
    mapping (address=>uint256) public balances;

    uint public MinSum;

    LogFile Log;

    bool intitalized;

    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }

    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }

    function Initialized()
    public
    {
        intitalized = true;
    }

    function Deposit()
    public
    payable
    {
        balances[msg.sender]+= msg.value;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }

    function Collect(uint _am)
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            // effects before interaction: debit first, then call
            balances[msg.sender]-=_am;
            if(msg.sender.call.value(_am)())
            {
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }

    function()
    public
    payable
    {
        Deposit();
    }

}



contract LogFile
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }

    Message[] public History;

    Message LastMsg;

    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}
