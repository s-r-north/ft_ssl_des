/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fmod.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: snorth <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/03/12 15:16:32 by snorth            #+#    #+#             */
/*   Updated: 2017/03/13 21:18:14 by snorth           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

double	ft_fmod(double nb, double div)
{
	double	ret;
	int		sign;

	sign = nb < 0 ? -1 : 1;
	if (div == 0 || nb * sign > 8e22 || div > 8e22 || div < -8e22)
		return (1e60);
	ret = nb - (div * (int)(nb / div));
	if (ret * sign < 0)
		ret *= -1;
	return (ret);
}
