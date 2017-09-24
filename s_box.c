#include "ft_ssl.h"
#include <time.h>

void	handle_sbox()
{
	int i;
	time_t t;
	uint32_t c;
	uint32_t r;
	i = -1;

	srand((unsigned) time(&t));
	while (++i < 8)
	{
		r = rand() % 4;
		c = rand() % 16;
		printf("sbox%u[%u][%u]: %u\n", i + 1, r, c, g_des_sbox[i][r][c]);
	}
}

int		main()
{
	handle_sbox();
}