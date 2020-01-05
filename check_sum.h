uint16_t ip_check_sum(uint16_t *buf,int len)
{
    uint16_t sum;
    for(sum=0; len>0; len--)
    {
        sum+=*buf++;
    }
    sum=(sum>>16)+(sum &0xFFFF);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}