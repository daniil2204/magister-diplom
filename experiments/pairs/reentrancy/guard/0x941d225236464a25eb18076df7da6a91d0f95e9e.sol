/*
 * Fixed version of smartbugs-curated reentrancy/0x941d225236464a25eb18076df7da6a91d0f95e9e.sol
 * (pair, fix style: guard).
 * Fix: a nonReentrant lock variable guards CashOut, so the re-entrant call cannot re-enter before
 * `balances` is written. The SC08 target stays (write after the call) but is refuted. Only the SC08
 * unit is scored on this version.
 * solc version inherited from the original (0.4.x).
 */

pragma solidity ^0.4.19;

contract ETH_FUND
{
    mapping (address => uint) public balances;

    uint public MinDeposit = 1 ether;

    Log TransferLog;

    uint lastBlock;

    bool private locked;

    modifier nonReentrant()
    {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function ETH_FUND(address _log)
    public
    {
        TransferLog = Log(_log);
    }

    function Deposit()
    public
    payable
    {
        if(msg.value > MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
            lastBlock = block.number;
        }
    }

    function CashOut(uint _am)
    public
    payable
    nonReentrant
    {
        if(_am<=balances[msg.sender]&&block.number>lastBlock)
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }

    function() public payable{}

}

contract Log
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
