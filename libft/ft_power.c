/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_power.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/08 20:19:58 by snorth            #+#    #+#             */
/*   Updated: 2017/04/16 23:23:36 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

double		ft_power(double nb, int pow)
{
	double	ret;
	int		sign;
	int		i;

	ret = 1;
	sign = 1;
	i = 0;
	if (pow < 0)
	{
		sign = -1;
		pow *= -1;
	}
	while (++i <= pow)
		ret *= nb;
	if (sign == -1)
		ret = nb == 0 ? 1e60 : 1 / ret;
	return (ret);
}
