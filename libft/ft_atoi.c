/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/02/27 11:47:49 by snorth            #+#    #+#             */
/*   Updated: 2017/03/10 00:38:06 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_atoi(const char *str)
{
	size_t			i;
	unsigned long	ret;
	int				sign;

	sign = 1;
	ret = 0;
	i = 0;
	while (str[i] == '\n' || str[i] == '\v' || str[i] == '\r' ||
			str[i] == '\f' || str[i] == '\t' || str[i] == ' ')
		i++;
	if (str[i] == '+' || str[i] == '-')
		sign = str[i++] == '-' ? -1 : 1;
	while (str[i] >= 48 && str[i] <= 57)
	{
		if (ret >= 922337203685477580 && str[i] > 55)
		{
			ret = (sign == 1) ? -1 : 0;
			return ((int)ret);
		}
		ret = (ret * 10) + (str[i] - 48);
		i++;
	}
	return ((int)ret * sign);
}
